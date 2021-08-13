import logging

from enum import Enum
from saas.helpers import write_json_to_file

logger = logging.getLogger('rti.status')


class State(Enum):
    INITIALISED = 'initialised'
    RUNNING = 'running'
    FAILED = 'failed'
    SUCCESSFUL = 'successful'

    @staticmethod
    def from_string(label):
        for s in [State.INITIALISED, State.RUNNING, State.FAILED, State.SUCCESSFUL]:
            if label == s.value:
                return s

        raise NotImplementedError


class StatusLogger:
    """
    StatusLogger keeps information (key-value pairs) for a job and syncs its contents to disk. This class is
    basically just a wrapper of a dictionary providing convenient functions.
    """

    def __init__(self, path):
        self.path = path
        self.content = {}
        self.update_all({
            'state': State.RUNNING.value
        })

    def update_state(self, state):
        self.content['state'] = state.value
        write_json_to_file(self.content, self.path)

    def get_state(self):
        return State(self.content['state'])

    def update(self, key, value):
        """
        Update the job status with a given key and value. The updated job status is synced to disk.
        """
        self.content[key] = value
        write_json_to_file(self.content, self.path)

    def update_all(self, content):
        """
        Update the job status with given content (i.e., dictionary). The updated job status is synced to disk.
        """
        self.content.update(content)
        write_json_to_file(self.content, self.path)

    def get(self, key=None):
        """
        Returns the value for a given key.
        """
        return self.content[key] if key else self.content

    def remove(self, key):
        """
        Removes an entry (if they exists)
        """
        self.content.pop(key, None)
        write_json_to_file(self.content, self.path)

    def remove_all(self, keys):
        """
        Removes multiple entries (if they exists) using a list of key.
        """
        for key in keys:
            self.content.pop(key, None)
        write_json_to_file(self.content, self.path)
