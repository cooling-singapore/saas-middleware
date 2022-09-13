import os
import traceback

from saascore.exceptions import SaaSException
from saascore.keystore.assets.credentials import GithubCredentials
from saascore.log import Logging

import docker

import saas.rti.adapters.base as base
from saas.rti.exceptions import DockerRuntimeError, BuildDockerImageError
from saas.rti.status import StatusLogger

logger = Logging.get('rti.adapters.docker')


def get_image_tag(proc_id: str) -> str:
    """
    Returns docker image tag as first 10 characters of proc id
    """
    return proc_id[:10]


def prune_image(proc_id: str) -> None:
    client = docker.from_env()
    # Remove image
    client.images.remove(get_image_tag(proc_id), noprune=False)
    # Remove any other intermediate images
    client.images.prune({'label': f'proc_id={proc_id}'})
    client.close()


class RTIDockerProcessorAdapter(base.RTIProcessorAdapter):
    def delete(self) -> None:
        pass

    def __init__(self, proc_id: str, gpp: dict, obj_content_path: str, jobs_path: str, node,
                 github_credentials: GithubCredentials) -> None:
        super().__init__(proc_id, gpp, jobs_path, node)

        self._gpp = gpp
        self._github_credentials = github_credentials

        self.docker_image_tag = get_image_tag(proc_id)

    def startup(self) -> None:
        logger.info(f"Building Docker image with tag: {self.docker_image_tag}")
        try:
            client = docker.from_env()
            client.images.build(path=os.path.join(os.path.dirname(__file__), "utilities"),
                                tag=self.docker_image_tag,
                                forcerm=True,  # remove intermediate containers
                                buildargs={"GIT_REPO": self._gpp["source"],
                                           "COMMIT_ID": self._gpp["commit_id"],
                                           "PROCESSOR_PATH": self._gpp["proc_path"],
                                           "PROC_CONFIG": self._gpp['proc_config'],
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

            # Detach and stream docker container output
            container = client.containers.run(self.docker_image_tag, full_working_directory,
                                              volumes={
                                                  full_working_directory: {'bind': '/working_directory', 'mode': 'rw'}
                                              },
                                              remove=True,  # Auto remove container once done
                                              detach=True)

            # Block and go through logs until container closes
            for log in container.logs(stream=True):
                lines = log.decode('utf-8').splitlines()

                for line in lines:
                    if line.startswith('trigger:output'):
                        self._handle_trigger_output(line, status, job_id, job_descriptor, working_directory)

                    if line.startswith('trigger:progress'):
                        self._handle_trigger_progress(line, status)

            client.close()

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            raise DockerRuntimeError({
                'job_id': job_id,
                'job_descriptor': job_descriptor,
                'working_directory': working_directory,
                'trace': trace
            })

    def _handle_trigger_output(self, line: str, status: StatusLogger, job_id: str,
                               task_descriptor: dict, working_directory: str) -> None:
        obj_name = line.split(':')[2]
        try:
            status.update(f"process_output:{obj_name}", 'push')
            self._push_data_object(job_id, obj_name, task_descriptor, working_directory, status)
            status.update(f"process_output:{obj_name}", 'done')
        except SaaSException as e:
            status.update(f"process_output:{obj_name}", f"failed: id={e.id} reason={e.reason}")

    def _handle_trigger_progress(self, line: str, status: StatusLogger) -> None:
        """
        Line is in the format `trigger:progress:<int>`
        """
        status.update('progress', line.split(':')[2])
