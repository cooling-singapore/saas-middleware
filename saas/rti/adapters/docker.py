import json
import logging
import os

import docker
from jsonschema import validate

from saas.cryptography.hashing import hash_json_object
from saas.rti.adapters.adapters import RTITaskProcessorAdapter
from saas.schemas import git_specification_schema

logger = logging.getLogger('rti.docker')


class RTIDockerProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, proc_id, descriptor, content_path, node):
        super().__init__(proc_id, node)
        self.proc_id = proc_id
        self.git_spec = self._read_git_spec(content_path)

        git_spec_hash = hash_json_object(self.git_spec).hex()[:10]
        self.docker_image_tag = f"{git_spec_hash}"

    @staticmethod
    def _read_git_spec(git_spec_path):
        with open(git_spec_path, 'rb') as f:
            git_spec = json.load(f)
        validate(instance=git_spec, schema=git_specification_schema)
        return git_spec

    # TODO: Catch exceptions and log output for docker commands
    def build_docker_image(self):
        client = docker.from_env()
        client.images.build(path=os.path.join(os.path.dirname(__file__), "utilities"),
                            tag=self.docker_image_tag,
                            buildargs={"GIT_REPO": self.git_spec["source"],
                                       "COMMIT_ID": self.git_spec["commit_id"],
                                       "PROCESSOR_PATH": self.git_spec["path"]})
        client.close()

    def run_docker_container(self, working_directory):
        client = docker.from_env()

        full_working_directory = os.path.realpath(working_directory)
        client.containers.run(self.docker_image_tag, full_working_directory,
                              volumes={
                                  full_working_directory: {'bind': '/working_directory', 'mode': 'rw'}
                              },
                              remove=True)
        client.close()

    def get_processor_descriptor(self):
        """
        Retrieves descriptor of processor from git repo cloned in the docker image

        :return: Descriptor of processor
        """
        client = docker.from_env()

        logs = client.containers.run(self.docker_image_tag,
                                     entrypoint=["cat",
                                                 f"/processor_repo/{self.git_spec['path']}/descriptor.json"],
                                     remove=True)
        descriptor = json.loads(logs.decode('utf-8'))
        client.close()

        return descriptor

    def startup(self):
        self.build_docker_image()

        processor_descriptor = self.get_processor_descriptor()
        self.parse_io_interface(processor_descriptor)

        logger.info(f"[{self.__class__.__name__}] startup: started processor '{self.proc_id}'")

    def execute(self, task_descriptor, working_directory, status_logger):
        try:
            self.run_docker_container(working_directory)
        except Exception as e:
            logger.error(e)
            return False
        return True
