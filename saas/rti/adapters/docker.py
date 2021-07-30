import json
import logging
import os

import docker
from jsonschema import validate

from saas.rti.adapters.adapters import RTITaskProcessorAdapter
from saas.schemas import git_specification_schema

logger = logging.getLogger('rti.adapters.docker')


def get_image_tag(proc_id):
    return proc_id[:10]


def prune_image(proc_id):
    client = docker.from_env()
    # Remove image
    client.images.remove(get_image_tag(proc_id), noprune=False)
    # Remove any other intermediate images
    client.images.prune({'label': f'proc_id={proc_id}'})
    client.close()


class RTIDockerProcessorAdapter(RTITaskProcessorAdapter):
    def __init__(self, proc_id, content_path, node):
        super().__init__(proc_id, node)
        self.proc_id = proc_id
        self.git_spec = self._read_git_spec(content_path)

        self.docker_image_tag = get_image_tag(proc_id)

        self._processor_descriptor = None

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
                            forcerm=True,  # remove intermediate containers
                            buildargs={"GIT_REPO": self.git_spec["source"],
                                       "COMMIT_ID": self.git_spec["commit_id"],
                                       "PROCESSOR_PATH": self.git_spec["path"],
                                       "PROC_ID": self.proc_id})
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
        logger.debug(f"{self.proc_id} descriptor: {descriptor}")
        client.close()

        return descriptor

    def descriptor(self):
        return self._processor_descriptor

    def startup(self):
        self.build_docker_image()

        self._processor_descriptor = self.get_processor_descriptor()
        self.parse_io_interface(self._processor_descriptor)

    def execute(self, task_descriptor, working_directory, status_logger):
        try:
            self.run_docker_container(working_directory)
        except Exception as e:
            logger.error(e)
            return False
        return True
