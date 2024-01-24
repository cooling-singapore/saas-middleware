import os
import threading
import traceback

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from saas.cli.exceptions import CLIRuntimeError
from saas.cli.helpers import CLICommand, Argument, prompt_for_string, prompt_if_missing
from saas.core.logging import Logging
from saas.rti.proxy import JOB_ENDPOINT_PREFIX
from saas.rti.schemas import JobStatus, Severity
from saas.sdk.processor import find_processors, ProcessorBase, ProgressListener, ProcessorRuntimeError

logger = Logging.get('cli.job_runner')


class JobWorker(threading.Thread):
    class ProgressListener(ProgressListener):
        def __init__(self, job_status: JobStatus) -> None:
            self._job_status = job_status

        def on_progress_update(self, progress: int) -> None:
            self._job_status.progress = progress

        def on_output_available(self, output_name: str) -> None:
            if output_name not in self._job_status.output:
                self._job_status.output[output_name] = None

        def on_message(self, severity: Severity, message: str) -> None:
            self._job_status.message = JobStatus.Message(severity=severity, content=message)

    def __init__(self, proc: ProcessorBase, wd_path: str) -> None:
        super().__init__()

        self._mutex = threading.Lock()
        self._proc = proc
        self._wd_path = wd_path
        self._status = JobStatus(state=JobStatus.State.INITIALISED, progress=0, output={}, notes={},
                                 job=None, reconnect=None, errors=[], message=None)

    def run(self) -> None:
        try:
            logger.info(f"begin processing job at {self._wd_path}")
            self._status.state = JobStatus.State.RUNNING

            self._proc.run(self._wd_path, JobWorker.ProgressListener(self._status), logger)

            with self._mutex:
                if self._status.state == JobStatus.State.CANCELLED:
                    logger.info(f"end processing job at {self._wd_path} -> CANCELLED")

                else:
                    logger.info(f"end processing job at {self._wd_path} -> POSTPROCESSING")
                    self._status.state = JobStatus.State.POSTPROCESSING

        except ProcessorRuntimeError as e:
            logger.error(f"end processing job at {self._wd_path} -> UNSUCCESSFUL: {e.reason}")
            with self._mutex:
                self._status.errors.append(JobStatus.Error(message=e.reason, content=e.content))
                self._status.state = JobStatus.State.FAILED

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            e = ProcessorRuntimeError(f'Unexpected Error: {str(e)}', details={'trace': trace})

            logger.error(f"end processing job at {self._wd_path} -> UNSUCCESSFUL: {e.reason}")
            with self._mutex:
                self._status.errors.append(JobStatus.Error(message=e.reason, exception=e.content))
                self._status.state = JobStatus.State.FAILED

    def status(self) -> JobStatus:
        with self._mutex:
            return self._status

    def interrupt(self) -> None:
        with self._mutex:
            logger.info(f"attempt to interrupt job at {self._wd_path}...")
            self._status.state = JobStatus.State.CANCELLED
            self._proc.interrupt()


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
        self._worker.interrupt()

        return self._worker.status()

    def execute(self, args: dict) -> None:
        prompt_if_missing(args, 'job_path', prompt_for_string, message="Enter path to the job:")
        prompt_if_missing(args, 'proc_path', prompt_for_string, message="Enter path to the processor:")
        prompt_if_missing(args, 'proc_name', prompt_for_string, message="Enter the name of the processor:")
        prompt_if_missing(args, 'rest_address', prompt_for_string, message="Enter address for REST service:")

        # does the job path exist?
        if not os.path.isdir(args['job_path']):
            raise CLIRuntimeError(f"Job path '{args['job_path']}' does not exist.")
        print(f"Using job path at {args['job_path']}")

        # does the processor path exist?
        if not os.path.isdir(args['proc_path']):
            raise CLIRuntimeError(f"Processor path '{args['proc_path']}' does not exist.")
        print(f"Using processor path at {args['proc_path']}")

        # find processors at the given location
        procs_by_name = find_processors(args['proc_path'])
        print(f"Found the following processors: {procs_by_name.keys()}")

        # do we have the processor we are looking for?
        proc: ProcessorBase = procs_by_name.get(args['proc_name'], None)
        if proc is None:
            raise CLIRuntimeError(f"No processor '{args['proc_name']}' found at '{args['proc_path']}'.")

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

        # start and wait for the worker thread to be finished
        self._worker.start()
        self._worker.join()
