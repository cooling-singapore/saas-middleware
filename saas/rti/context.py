from __future__ import annotations

import json
import time
from threading import Lock, Thread
from typing import Union, Optional

from saas.core.exceptions import ExceptionContent, SaaSRuntimeException
from saas.core.logging import Logging
from saas.dor.schemas import CDataObject
from saas.rti.schemas import JobStatus, Job, ReconnectInfo

logger = Logging.get('rti.helpers')


class JobContext(Thread):
    def __init__(self, path: str, job: Job, reconnect: ReconnectInfo = None) -> None:
        super().__init__()

        self._mutex = Lock()
        self._path = path
        self._status = JobStatus(state=JobStatus.State.INITIALISED, progress=0, output={}, notes={}, job=job,
                                 reconnect=reconnect)
        self._tasks = []
        self._exception = None
        self._sync()

    def run(self):
        logger.debug(f"[{self._status.job.id}] context worker started")
        while self._status.state in [JobStatus.State.INITIALISED, JobStatus.State.RUNNING] or len(self._tasks) > 0:
            # get a task (if any)
            with self._mutex:
                task = self._tasks[0] if len(self._tasks) > 0 else None

            # do we have a task?
            if task:
                # try to perform it
                try:
                    target = task['target']
                    args = task['args']
                    target(*args)

                    # remove the task once it's done
                    with self._mutex:
                        self._tasks.remove(task)

                except SaaSRuntimeException as e:
                    logger.error(f"[{self._status.job.id}] context worker encountered an exception: {e.reason} "
                                 f"{e.details}")

                    # set the exception
                    with self._mutex:
                        self._exception = e

                    break

            else:
                time.sleep(0.25)

        logger.debug(f"[{self._status.job.id}] context worker for terminated")

    def _sync(self):
        with open(self._path, 'w') as f:
            json.dump(self._status.dict(), f, indent=4)

    def cancel(self) -> None:
        with self._mutex:
            self._status.state = JobStatus.State.CANCELLED

    @property
    def status(self) -> JobStatus:
        with self._mutex:
            return self._status.copy()

    @property
    def job(self) -> Job:
        with self._mutex:
            return self._status.job

    @property
    def reconnect_info(self) -> Optional[ReconnectInfo]:
        with self._mutex:
            return self._status.reconnect

    def add_task(self, target, args=()) -> None:
        with self._mutex:
            self._tasks.append({
                'target': target,
                'args': args
            })

    def n_tasks(self) -> int:
        with self._mutex:
            return len(self._tasks)

    def exception(self) -> Optional[SaaSRuntimeException]:
        with self._mutex:
            return self._exception

    def add_reconnect_info(self, paths: dict[str, str], pid: str, pid_paths: dict[str, str]) -> None:
        with self._mutex:
            self._status.reconnect = ReconnectInfo(paths=paths, pid=pid, pid_paths=pid_paths)
            self._sync()

    @property
    def state(self) -> JobStatus.State:
        with self._mutex:
            return self._status.state

    @state.setter
    def state(self, new_state: JobStatus.State) -> None:
        with self._mutex:
            self._status.state = new_state
            self._sync()

    @property
    def progress(self) -> int:
        with self._mutex:
            return self._status.progress

    @progress.setter
    def progress(self, new_progress: int) -> None:
        with self._mutex:
            self._status.progress = new_progress
            self._sync()

    def message(self, message: str) -> None:
        with self._mutex:
            self._status.notes['message'] = message
            self._sync()

    def get_output(self, obj_name: str) -> CDataObject:
        with self._mutex:
            return self._status.output[obj_name]

    def set_output(self, obj_name: str, meta: CDataObject) -> None:
        with self._mutex:
            self._status.output[obj_name] = meta
            self._sync()

    def make_note(self, key: str, note: Union[str, int, float, bool, dict, list]) -> None:
        with self._mutex:
            self._status.notes[key] = note
            self._sync()

    def get_note(self, key: str, default: Union[str, int, float, bool, dict, list] = None) -> Union[str, int, float,
                                                                                                    bool, dict, list]:
        with self._mutex:
            return self._status.notes.get(key, default)

    def remove_note(self, key: str) -> None:
        with self._mutex:
            self._status.notes.pop(key, None)
            self._sync()

    def add_error(self, message: str, exception: ExceptionContent) -> None:
        with self._mutex:
            error = JobStatus.Error(message=message, exception=exception)
            if self._status.errors:
                self._status.errors.append(error)
            else:
                self._status.errors = [error]
