import os
import re
import traceback
from contextlib import contextmanager

import paramiko
from saascore.exceptions import SaaSException
from saascore.keystore.assets.credentials import GithubCredentials, SSHCredentials
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


def add_ssh_host_keys(host: str, username: str, password: str = None, key_path: str = None):
    client = paramiko.client.SSHClient()
    client.load_host_keys(os.path.expanduser(os.path.join("~", ".ssh", "known_hosts")))
    # TODO: Might be dangerous to auto accept host key if it changes
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    client.connect(host, username=username, key_filename=key_path, password=password)


def add_host_to_ssh_config(host_id: str, host: str, username: str, key_path: str):
    config_path = os.path.expanduser("~/.ssh/config")
    ssh_config = paramiko.config.SSHConfig.from_path(config_path)

    if host_id not in ssh_config.get_hostnames():
        ssh_host_template = f"\n### Added by saas-mw\n" \
                            f"Host {host_id}\n" \
                            f"  HostName {host}\n" \
                            f"  User {username}\n" \
                            f"  IdentityFile {key_path}\n" \
                            f"###\n"
        with open(config_path, "a") as f:
            f.write(ssh_host_template)


def remove_host_from_ssh_config(host_id: str):
    """
    Removes host from config with the format:
    Host name
      Hostname host
      User username
      IdentityFile file
    """
    config_path = os.path.expanduser("~/.ssh/config")
    ssh_config = paramiko.config.SSHConfig.from_path(config_path)

    if host_id in ssh_config.get_hostnames():
        regexp = re.compile(f"\n### Added by saas-mw\n"
                            f"Host {host_id}\n"
                            f"(\n|.)*?"
                            f"###\n")

        with open(config_path, "r") as f:
            config = f.read()

        with open(config_path, "w") as f:
            new_config = regexp.sub("", config)
            f.write(new_config)


class RTIDockerProcessorAdapter(base.RTIProcessorAdapter):
    def __init__(self, proc_id: str, gpp: dict, jobs_path: str, node,
                 ssh_credentials: SSHCredentials = None,
                 github_credentials: GithubCredentials = None) -> None:
        super().__init__(proc_id, gpp, jobs_path, node)

        self._gpp = gpp
        self._ssh_credentials = ssh_credentials
        self._github_credentials = github_credentials

        self.docker_image_tag = get_image_tag(proc_id)

    @contextmanager
    def get_docker_client(self):
        environment = os.environ

        # try to use remote docker if remote host is found
        # user must make sure that the login has permission to run commands on the remote host
        # e.g. sudo usermod -aG docker username
        if self._ssh_credentials:
            login = self._ssh_credentials.login
            host = self._ssh_credentials.host
            key = self._ssh_credentials.key

            # Make sure host keys are added
            add_ssh_host_keys(host, login, key_path=key)
            # Add host to ssh config
            add_host_to_ssh_config(self._proc_id, host, login, key)

            environment["DOCKER_HOST"] = f"ssh://{self._proc_id}"

        client = docker.from_env(environment=environment)
        try:
            yield client
        finally:
            client.close()

    def startup(self) -> None:
        logger.info(f"Building Docker image with tag: {self.docker_image_tag}")
        try:
            with self.get_docker_client() as client:
                client.images.build(path=os.path.join(os.path.dirname(__file__), "utilities"),
                                    tag=self.docker_image_tag,
                                    forcerm=True,  # remove intermediate containers
                                    buildargs={"GIT_REPO": self._gpp["source"],
                                               "COMMIT_ID": self._gpp["commit_id"],
                                               "PROCESSOR_PATH": self._gpp["proc_path"],
                                               "PROC_CONFIG": self._gpp['proc_config'],
                                               "PROC_ID": self._proc_id})

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            raise BuildDockerImageError({
                'trace': trace
            })

    def shutdown(self) -> None:
        pass

    def execute(self, job_id: str, job_descriptor: dict, working_directory: str, status: StatusLogger) -> None:
        try:
            with self.get_docker_client() as client:
                full_working_directory = os.path.realpath(working_directory)

                # Detach and stream docker container output
                container = client.containers.run(self.docker_image_tag, full_working_directory,
                                                  volumes={
                                                      full_working_directory: {
                                                          'bind': '/working_directory', 'mode': 'rw'
                                                      }
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

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            raise DockerRuntimeError({
                'job_id': job_id,
                'job_descriptor': job_descriptor,
                'working_directory': working_directory,
                'trace': trace
            })

    def delete(self) -> None:
        # FIXME: Might not be thread safe
        # Remove entry added to ssh config
        if self._ssh_credentials:
            remove_host_from_ssh_config(self._proc_id)

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
