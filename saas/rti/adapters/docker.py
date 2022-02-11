import json
import os
import traceback

from saascore.log import Logging

import docker

import saas.rti.adapters.base as base
from saas.rti.exceptions import DockerRuntimeError, BuildDockerImageError
from saas.rti.status import StatusLogger

logger = Logging.get('rti.adapters.docker')


def get_image_tag(proc_id: str) -> str:
    return proc_id[:10]


def prune_image(proc_id: str) -> None:
    client = docker.from_env()
    # Remove image
    client.images.remove(get_image_tag(proc_id), noprune=False)
    # Remove any other intermediate images
    client.images.prune({'label': f'proc_id={proc_id}'})
    client.close()


class RTIDockerProcessorAdapter(base.RTIProcessorAdapter):
    def __init__(self, proc_id: str, gpp: dict, obj_content_path: str, jobs_path: str, node) -> None:
        super().__init__(proc_id, gpp, jobs_path, node)

        with open(obj_content_path, 'rb') as f:
            self._gpp = json.load(f)

        self.docker_image_tag = get_image_tag(proc_id)

    def startup(self) -> None:
        try:
            client = docker.from_env()
            client.images.build(path=os.path.join(os.path.dirname(__file__), "utilities"),
                                tag=self.docker_image_tag,
                                forcerm=True,  # remove intermediate containers
                                buildargs={"GIT_REPO": self._gpp["source"],
                                           "COMMIT_ID": self._gpp["commit_id"],
                                           "PROCESSOR_PATH": self._gpp["proc_path"],
                                           "PROC_ID": self._proc_id})
            client.close()

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            raise BuildDockerImageError({
                'trace': trace
            })

    def shutdown(self) -> None:
        pass

    def execute(self, job_id: str, job_descriptor: dict, working_directory: str, status: StatusLogger) -> None:
        try:
            client = docker.from_env()

            full_working_directory = os.path.realpath(working_directory)
            client.containers.run(self.docker_image_tag, full_working_directory,
                                  volumes={
                                      full_working_directory: {'bind': '/working_directory', 'mode': 'rw'}
                                  },
                                  remove=True)
            client.close()

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            raise DockerRuntimeError({
                'job_id': job_id,
                'job_descriptor': job_descriptor,
                'working_directory': working_directory,
                'trace': trace
            })
