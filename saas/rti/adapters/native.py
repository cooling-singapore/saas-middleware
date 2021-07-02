import json
import os
import subprocess

from jsonschema import validate

from saas.rti.adapters.adapters import RTITaskProcessorAdapter
from saas.rti.adapters.utilities.processor_scripts import deploy_git_processor, get_processor
from saas.schemas import git_specification_schema


class RTINativeProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, proc_id, descriptor, content_path, node):
        super().__init__(proc_id, node)
        self.local_git_path = os.path.join(node.datastore(), '_git_repos', proc_id)
        self.git_spec = self._read_git_spec(content_path)

        self.processor_path = None
        self.processor_descriptor = None

    @staticmethod
    def _read_git_spec(git_spec_path):
        with open(git_spec_path, 'rb') as f:
            git_spec = json.load(f)
        validate(instance=git_spec, schema=git_specification_schema)
        return git_spec

    @property
    def log_dir(self):
        log_dir = os.path.join(self._node.datastore(), 'logs')
        if not os.path.exists(log_dir):
            os.mkdir(log_dir)
        return log_dir

    def startup(self):
        deploy_git_processor(self.local_git_path, self.git_spec, self.log_dir)

        processor_path, processor_descriptor = get_processor(self.local_git_path, self.git_spec)
        self.processor_path = processor_path
        self.processor_descriptor = processor_descriptor

        self.parse_io_interface(self.processor_descriptor)

    def execute(self, task_descriptor, working_directory, status_logger):
        venv_py_path = os.path.join(self.local_git_path, 'venv', 'bin', 'python')
        subprocess.run([venv_py_path, self.processor_path, working_directory], check=True)
        return True
