from __future__ import annotations

from enum import Enum
from typing import Union

from saas import helpers
from saas.log import Logging

logger = Logging.get('rti.status')


class State(Enum):
    INITIALISED = 'initialised'
    RUNNING = 'running'
    FAILED = 'failed'
    TIMEOUT = 'timeout'
    SUCCESSFUL = 'successful'


class StatusLogger:
    """
    StatusLogger keeps information (key-value pairs) for a job and syncs its contents to disk. This class is
    basically just a wrapper of a dictionary providing convenient functions.
    """

    def __init__(self, path: str) -> None:
        self._path = path
        self._content = {}
        self.update_all({
            'state': State.RUNNING.value
        })

    def update_state(self, state: State) -> None:
        self._content['state'] = state.value
        helpers.write_json_to_file(self._content, self._path)

    def get_state(self) -> State:
        return State(self._content['state'])

    def update(self, key: str, value: Union[str, dict, list]) -> None:
        self._content[key] = value
        helpers.write_json_to_file(self._content, self._path)

    def update_all(self, content: dict) -> None:
        self._content.update(content)
        helpers.write_json_to_file(self._content, self._path)

    def get(self, key: str = None, default: Union[str, dict, list] = None) -> Union[str, dict, list]:
        return self._content.get(key, default) if key else self._content

    def remove(self, key: str) -> None:
        self._content.pop(key, None)
        helpers.write_json_to_file(self._content, self._path)

    def remove_all(self, keys: list[str]) -> None:
        for key in keys:
            self._content.pop(key, None)
        helpers.write_json_to_file(self._content, self._path)
