from __future__ import annotations

import json
import threading
from threading import Lock
from typing import Union, Optional

from saas.core.exceptions import ExceptionContent
from saas.core.logging import Logging
from saas.dor.schemas import CDataObject
from saas.rti.schemas import JobStatus, Job, ReconnectInfo

logger = Logging.get('rti.helpers')


class JobContext:
    def __init__(self, path: str, job: Job, reconnect: ReconnectInfo = None) -> None:
        self._mutex = Lock()
        self._path = path
        self._content = JobStatus(state=JobStatus.State.INITIALISED, progress=0, output={}, notes={}, job=job,
                                  reconnect=reconnect)
        self._threads = {}
        self._cancelled = False
        self._sync()

    def _sync(self):
        with open(self._path, 'w') as f:
            json.dump(self._content.dict(), f, indent=4)

    def cancel(self) -> None:
        with self._mutex:
            self._cancelled = True

    @property
    def content(self) -> JobStatus:
        with self._mutex:
            return self._content.copy()

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    @property
    def job(self) -> Job:
        with self._mutex:
            return self._content.job

    @property
    def reconnect(self) -> Optional[ReconnectInfo]:
        with self._mutex:
            return self._content.reconnect

    def add_thread(self, obj_name: str, target, args=()) -> None:
        with self._mutex:
            thread = threading.Thread(target=target, args=args)
            self._threads[obj_name] = thread

        thread.start()

    def pop_thread(self, obj_name: str) -> None:
        with self._mutex:
            self._threads.pop(obj_name, None)

    def n_threads(self) -> int:
        with self._mutex:
            return len(self._threads)

    def add_reconnect_info(self, paths: dict[str, str], pid: str, pid_paths: dict[str, str]) -> None:
        with self._mutex:
            self._content.reconnect = ReconnectInfo(paths=paths, pid=pid, pid_paths=pid_paths)
            self._sync()

    @property
    def state(self) -> JobStatus.State:
        with self._mutex:
            return self._content.state

    @state.setter
    def state(self, new_state: JobStatus.State) -> None:
        with self._mutex:
            self._content.state = new_state
            self._sync()

    @property
    def progress(self) -> int:
        with self._mutex:
            return self._content.progress

    @progress.setter
    def progress(self, new_progress: int) -> None:
        with self._mutex:
            self._content.progress = new_progress
            self._sync()

    def get_output(self, obj_name: str) -> CDataObject:
        with self._mutex:
            return self._content.output[obj_name]

    def set_output(self, obj_name: str, meta: CDataObject) -> None:
        with self._mutex:
            self._content.output[obj_name] = meta
            self._sync()

    def make_note(self, key: str, note: Union[str, int, float, bool, dict, list]) -> None:
        with self._mutex:
            self._content.notes[key] = note
            self._sync()

    def get_note(self, key: str, default: Union[str, int, float, bool, dict, list] = None) -> Union[str, int, float,
                                                                                                    bool, dict, list]:
        with self._mutex:
            return self._content.notes.get(key, default)

    def remove_note(self, key: str) -> None:
        with self._mutex:
            self._content.notes.pop(key, None)
            self._sync()

    def add_error(self, message: str, exception: ExceptionContent) -> None:
        with self._mutex:
            error = JobStatus.Error(message=message, exception=exception)
            if self._content.errors:
                self._content.errors.append(error)
            else:
                self._content.errors = [error]
