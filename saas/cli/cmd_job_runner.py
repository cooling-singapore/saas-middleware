import json
import logging
import os
import threading
import time
import traceback
from typing import Optional

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLICommand, Argument, prompt_for_string, prompt_if_missing
from saas.core.logging import Logging
from saas.dor.schemas import ProcessorDescriptor
from saas.rti.proxy import JOB_ENDPOINT_PREFIX, JobRESTProxy
from saas.rti.schemas import JobStatus, Severity, JobResult, ExitCode
from saas.sdk.processor import find_processors, ProcessorBase, ProgressListener, ProcessorRuntimeError


class JobWorker(threading.Thread, ProgressListener):
    def __init__(self, proc: ProcessorBase, wd_path: str, log_level: int = logging.INFO) -> None:
        super().__init__()

        self._mutex = threading.Lock()
        self._proc = proc
        self._wd_path = wd_path
        self._interrupted = False

        # setup logger
        log_path = os.path.join(wd_path, 'job.log')
        self._logger = Logging.get('cli.job_runner', level=log_level, custom_log_path=log_path)

        # initialise job status
        self._job_status = JobStatus(progress=0, output={}, notes={}, errors=[], message=None)
        self._store_job_status()

    def on_progress_update(self, progress: int) -> None:
        self._logger.info(f"on_progress_update: progress={progress}")
        self._job_status.progress = progress
        self._store_job_status()

    def on_output_available(self, output_name: str) -> None:
        if output_name not in self._job_status.output:
            self._logger.info(f"on_output_available: output_name={output_name}")
            self._job_status.output[output_name] = None
            self._store_job_status()

    def on_message(self, severity: Severity, message: str) -> None:
        self._logger.info(f"on_message: severity={severity} message={message}")
        self._job_status.message = JobStatus.Message(severity=severity, content=message)
        self._store_job_status()

    def _store_job_status(self) -> None:
        job_status_path = os.path.join(self._wd_path, 'job.status')
        with open(job_status_path, 'w') as f:
            json.dump(self._job_status.dict(), f, indent=2)

    def _write_exitcode(self, exitcode: ExitCode, e: Exception = None) -> None:
        exitcode_path = os.path.join(self._wd_path, 'job.exitcode')
        with open(exitcode_path, 'w') as f:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__)) if e else None
            result = JobResult(exitcode=exitcode, trace=trace)
            json.dump(result.dict(), f, indent=2)

    def run(self) -> None:
        try:
            self._logger.info(f"begin processing job at {self._wd_path}")

            self._proc.run(self._wd_path, self, self._logger)

            if self._interrupted:
                self._logger.info(f"end processing job at {self._wd_path} -> INTERRUPTED")
                self._write_exitcode(ExitCode.INTERRUPTED)

            else:
                self._logger.info(f"end processing job at {self._wd_path} -> DONE")
                self._write_exitcode(ExitCode.DONE)

        except ProcessorRuntimeError as e:
            self._logger.error(f"end processing job at {self._wd_path} -> FAILED: {e.reason}")
            self._write_exitcode(ExitCode.ERROR, e)

        except Exception as e:
            self._logger.error(f"end processing job at {self._wd_path} -> FAILED: {e}")
            self._write_exitcode(ExitCode.ERROR, e)

    def status(self) -> JobStatus:
        with self._mutex:
            return self._job_status

    def interrupt(self) -> JobStatus:
        with self._mutex:
            self._logger.info(f"attempt to interrupt job at {self._wd_path}...")
            self._interrupted = True
            self._proc.interrupt()
            return self._job_status


def write_exitcode(job_path: str, exitcode: ExitCode, e: Exception = None) -> None:
    exitcode_path = os.path.join(job_path, 'runner.exitcode')
    with open(exitcode_path, 'w') as f:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__)) if e else None
        result = JobResult(exitcode=exitcode, trace=trace)
        json.dump(result.dict(), f, indent=2)


def wait_for_job_runner(job_path: str, rest_address: (str, int)) -> \
        (JobResult, Optional[JobResult], Optional[JobStatus]):
    job_exitcode_path = os.path.join(job_path, 'job.exitcode')
    runner_exitcode_path = os.path.join(job_path, 'runner.exitcode')
    job_status_path = os.path.join(job_path, 'job.status')
    proxy = JobRESTProxy(rest_address)
    while True:
        status: JobStatus = proxy.job_status()
        if status is None:
            # is there a job.exitcode and runner.exitcode file?
            has_runner_exitcode = os.path.isfile(runner_exitcode_path)
            has_job_exitcode = os.path.isfile(job_exitcode_path)
            has_job_status = os.path.isfile(job_status_path)
            if has_runner_exitcode:
                runner_result = JobResult.parse_file(runner_exitcode_path)
                job_result = JobResult.parse_file(job_exitcode_path) if has_job_exitcode else None
                status = JobStatus.parse_file(job_status_path) if has_job_status else None
                return runner_result, job_result, status

            else:
                pass

        else:
            pass

        time.sleep(0.5)


class JobRunner(CLICommand):
    def __init__(self):
        super().__init__('run', 'runs a job with a processor', arguments=[
            Argument('--job-path', dest='job_path', action='store', help=f"path to the job"),
            Argument('--proc-path', dest='proc_path', action='store', help=f"path to the processor"),
            Argument('--proc-name', dest='proc_name', action='store', help=f"name of the processor"),
            Argument('--rest-address', dest='rest_address', action='store',
                     help=f"address used by the REST job interface")
        ])

        self._worker = None

    async def job_status(self) -> JobStatus:
        return self._worker.status()

    async def job_cancel(self) -> JobStatus:
        # interrupt the processor. note: whether this request is honored or even implemented depends on the
        # actual processor.
        return self._worker.interrupt()

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'job_path', prompt_for_string, message="Enter path to the job:")
        prompt_if_missing(args, 'proc_path', prompt_for_string, message="Enter path to the processor:")
        prompt_if_missing(args, 'rest_address', prompt_for_string, message="Enter address for REST service:")

        # does the job path exist?
        if not os.path.isdir(args['job_path']):
            raise CLIRuntimeError(f"Job path '{args['job_path']}' does not exist.")
        print(f"Using job path at {args['job_path']}")

        try:
            # does the processor path exist?
            if not os.path.isdir(args['proc_path']):
                raise CLIRuntimeError(f"Processor path '{args['proc_path']}' does not exist.")
            print(f"Using processor path at {args['proc_path']}")

            # find processors at the given location
            procs_by_name = find_processors(args['proc_path'])
            print(f"Found the following processors: {list(procs_by_name.keys())}")

            # do we have a processor name?
            if 'proc_name' not in args or args['proc_name'] is None:
                # try to read the descriptor in the proc path
                descriptor_path = os.path.join(args['proc_path'], 'descriptor.json')
                if not os.path.isfile(descriptor_path):
                    raise CLIRuntimeError(f"No processor descriptor found at '{args['proc_path']}'.")

                # read the descriptor
                with open(descriptor_path) as f:
                    # try to get the processor by the descriptor name
                    descriptor = ProcessorDescriptor.parse_obj(json.load(f))
                    args['proc_name'] = descriptor.name

            # do we have the processor we are looking for?
            proc: ProcessorBase = procs_by_name.get(args['proc_name'], None)
            if proc is None:
                raise CLIRuntimeError(f"No processor '{args['proc_name']}' found at '{args['proc_path']}'.")
            print(f"Found processor '{args['proc_name']}' at '{args['proc_path']}'")

            app = FastAPI(openapi_url='/openapi.json', docs_url='/docs')

            # setup CORS
            app.add_middleware(
                CORSMiddleware,
                allow_origins=['*'],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )

            # register endpoints
            app.get(JOB_ENDPOINT_PREFIX+'/status', response_model=JobStatus,
                    description=self.job_status.__doc__)(self.job_status)
            app.put(JOB_ENDPOINT_PREFIX+'/cancel', response_model=JobStatus,
                    description=self.job_cancel.__doc__)(self.job_cancel)

            # create the job worker
            self._worker = JobWorker(proc, args['job_path'])

            # create and start the REST server
            address = args['rest_address'].split(":")
            server_thread = threading.Thread(target=uvicorn.run, args=(app,), daemon=True,
                                             kwargs={"host": address[0], "port": int(address[1]), "log_level": "info"})
            server_thread.start()

            # run the worker
            self._worker.run()

            write_exitcode(args['job_path'], ExitCode.DONE)

        except Exception as e:
            write_exitcode(args['job_path'], ExitCode.ERROR, e)
