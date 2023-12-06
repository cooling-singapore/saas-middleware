import os
import threading
import time
import traceback
from typing import Tuple

import uvicorn
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from saas import meta
from saas.core.logging import Logging
from saas.rest.proxy import EndpointProxy, get_proxy_prefix
from saas.rti.schemas import JobStatus
from saas.sdk.processor import ProcessorRuntimeError, ProcessorBase, ProgressListener, Severity

app = FastAPI()
logger = Logging.get(__name__)

PROCESSOR_ENDPOINT_PREFIX = "/api/v1/proc"


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


class ProcessorRESTWrapper:
    def __init__(self, proc: ProcessorBase, address: (str, int), jobs_root_path: str) -> None:
        self._mutex = threading.Lock()
        self._proc = proc
        self._address = address
        self._jobs_root_path = jobs_root_path

        self._server = None
        self._worker = None

        self._api = FastAPI(
            openapi_url='/openapi.json',
            docs_url='/docs'
        )

        # register endpoints
        self._api.post(PROCESSOR_ENDPOINT_PREFIX+'/job/submit/{job_id}', response_model=None,
                       description=self.job_submit.__doc__)(self.job_submit)
        self._api.get(PROCESSOR_ENDPOINT_PREFIX+'/job/status', response_model=JobStatus,
                      description=self.job_status.__doc__)(self.job_status)
        self._api.delete(PROCESSOR_ENDPOINT_PREFIX+'/job/cancel', response_model=JobStatus,
                         description=self.job_cancel.__doc__)(self.job_cancel)

    async def job_submit(self, job_id: str) -> None:
        with self._mutex:
            if self._worker is None:
                # does the job working directory exist?
                wd_path = os.path.join(self._jobs_root_path, job_id)
                if not os.path.isdir(wd_path):
                    raise ProcessorRuntimeError(f"Job working directory not found at '{wd_path}'")

                # create the worker thread
                self._worker = JobWorker(self._proc, wd_path)
                self._worker.start()

            else:
                raise ProcessorRuntimeError(f"Job worker already exists, not accepting jobs")

        # # does the job descriptor exist?
        # job_descriptor_path = os.path.join(wd_path, 'job_descriptor.json')
        # if not os.path.isfile(job_descriptor_path):
        #     raise ProcessorRuntimeError(f"Job descriptor not found at '{job_descriptor_path}'")

    async def job_status(self) -> JobStatus:
        with self._mutex:
            # is there a job?
            if self._worker is None:
                raise ProcessorRuntimeError('No active job')

            return self._worker.status()

    async def job_cancel(self) -> JobStatus:
        with self._mutex:
            # is there a job?
            if self._worker is None:
                raise ProcessorRuntimeError('No active job')

            # interrupt the processor. note: whether this request is honored or even implemented depends on the
            # actual processor.
            self._worker.interrupt()

            return self._worker.status()

    def startup(self) -> None:
        with self._mutex:
            if self._server is None:
                # self._api.on_event("shutdown")(self._close)

                # update the openapi schema
                self._api.openapi_schema = get_openapi(
                    title='Processor REST Wrapper',
                    version=meta.__version__,
                    description="This application wraps a SaaS processor with a simple REST interface.",
                    routes=self._api.routes
                )

                @self._api.exception_handler(ProcessorRuntimeError)
                async def exception_handler(_: Request, exception: ProcessorRuntimeError):
                    return JSONResponse(
                        status_code=500,
                        content=exception.content.dict()
                    )

                # setup CORS
                self._api.add_middleware(
                    CORSMiddleware,
                    allow_origins=['*'],
                    allow_credentials=True,
                    allow_methods=["*"],
                    allow_headers=["*"],
                )

                logger.info("REST service starting up...")
                self._server = threading.Thread(target=uvicorn.run, args=(self._api,), daemon=True,
                                                kwargs={
                                                    "host": self._address[0],
                                                    "port": self._address[1],
                                                    "log_level": "info"
                                                })

                self._server.start()
                time.sleep(1)
                # await asyncio.sleep(0.1)

            else:
                logger.warning("REST service asked to start up but thread already exists! Ignoring...")

    # def shutdown(self) -> None:
    #     if self._thread is None:
    #         logger.warning("REST service asked to shut down but thread does not exist! Ignoring...")
    #
    #     else:
    #         logger.info("REST service shutting down...")
    #         # there is no way to terminate a thread...
    #         # self._thread.terminate()


class ProcessorRESTProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int), credentials: (str, str) = None,
                 endpoint_prefix: Tuple[str, str] = get_proxy_prefix(PROCESSOR_ENDPOINT_PREFIX)):
        super().__init__(endpoint_prefix, remote_address, credentials=credentials)

    def job_submit(self, job_id: str) -> None:
        self.post(f"job/submit/{job_id}")

    def job_status(self) -> JobStatus:
        result = self.get("job/status")
        return JobStatus.parse_obj(result)

    def job_cancel(self) -> JobStatus:
        result = self.delete("job/cancel")
        return JobStatus.parse_obj(result)
