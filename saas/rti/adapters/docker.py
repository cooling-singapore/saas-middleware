import io
import os
import re
import shutil
import tarfile
import tempfile
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Optional

import paramiko

import docker
from docker.errors import BuildError
from docker.models.containers import Container

import saas.rti.adapters.base as base
from saas.core.exceptions import SaaSRuntimeException, ExceptionContent
from saas.core.logging import Logging
from saas.rti.exceptions import DockerRuntimeError, BuildDockerImageError
from saas.dor.schemas import GitProcessorPointer
from saas.core.schemas import GithubCredentials, SSHCredentials
from saas.rti.schemas import JobStatus

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


def clone_github_repo(gpp: GitProcessorPointer, repo_path: str, github_credentials: GithubCredentials = None):
    git_source = gpp.source
    commit_id = gpp.commit_id

    if github_credentials:
        login = github_credentials.login
        token = github_credentials.personal_access_token
        git_source = git_source.replace("github.com", f"{login}:{token}@github.com")

    cmd1 = f"git clone {git_source} {repo_path}"
    cmd2 = f"cd {repo_path} && git checkout {commit_id}"

    base.run_command(cmd1)
    base.run_command(cmd2)


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
    def __init__(self, proc_id: str, gpp: GitProcessorPointer, state_wrapper: base.ProcessorStateWrapper,
                 node, jobs_path: str, job_concurrency: bool,
                 ssh_credentials: SSHCredentials = None, github_credentials: GithubCredentials = None) -> None:

        super().__init__(proc_id, gpp, state_wrapper, node, jobs_path, job_concurrency)

        self._gpp = gpp
        self._ssh_credentials = ssh_credentials
        self._github_credentials = github_credentials

        self.docker_image_tag = get_image_tag(proc_id)
        self.container: Optional[Container] = None
        self.container_working_directory = "/working_directory"

    @property
    def using_remote(self):
        return self._ssh_credentials is not None

    @contextmanager
    def get_docker_client(self):
        environment = os.environ

        # try to use remote docker if remote host is found
        # user must make sure that the login has permission to run commands on the remote host
        # e.g. sudo usermod -aG docker username
        if self.using_remote:
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
            # Setup docker build context
            with tempfile.TemporaryDirectory() as tempdir:
                dockerfile_path = os.path.join(os.path.dirname(__file__), "utilities", "Dockerfile")
                shutil.copyfile(dockerfile_path, os.path.join(tempdir, "Dockerfile"))

                # Clone git repo to temp directory
                repo_path = os.path.join(tempdir, "processor_repo")
                clone_github_repo(self._gpp, repo_path, self._github_credentials)

                with self.get_docker_client() as client:
                    image, info = client.images.build(path=tempdir,
                                                      tag=self.docker_image_tag,
                                                      forcerm=True,  # remove intermediate containers
                                                      buildargs={"PROCESSOR_PATH": self._gpp.proc_path,
                                                                 "PROC_CONFIG": self._gpp.proc_config,
                                                                 "PROC_ID": self._proc_id})

        except BuildError as e:
            print(e.msg)
            for log in e.build_log:
                print(log.get("stream"))
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            raise BuildDockerImageError({
                'trace': trace
            }) from e

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            raise BuildDockerImageError({
                'trace': trace
            }) from e

    def shutdown(self) -> None:
        # Make sure that the container is removed
        if self.container is not None:
            logger.warning("Docker container seems to be still running during shutdown. Force removing it...")
            self.container.remove(force=True)
            self.container = None

    def begin_job_execution(self, wd_path: str, context: base.JobContext) -> None:
        try:
            with self.get_docker_client() as client:
                client: docker.DockerClient
                full_working_directory = os.path.realpath(wd_path)

                # REMOTE
                if self.using_remote:
                    # Send input files to remote container before running
                    self.container = client.containers.create(self.docker_image_tag)

                    stream = io.BytesIO()
                    with tarfile.open(fileobj=stream, mode='w|') as tar:
                        for obj_name in self._input_interface:
                            local_path = os.path.join(full_working_directory, obj_name)
                            with open(local_path, 'rb') as f:
                                info = tar.gettarinfo(fileobj=f)
                                info.name = os.path.basename(local_path)
                                tar.addfile(info, f)

                    self.container.put_archive(self.container_working_directory, stream.getvalue())

                # LOCAL
                else:
                    # Create container with local directory attached
                    self.container = client.containers.create(self.docker_image_tag,
                                                              volumes={
                                                                  full_working_directory: {
                                                                      'bind': self.container_working_directory,
                                                                      'mode': 'rw'
                                                                  }
                                                              })

                self.container.start()

            # make it resumable
            context.put_note('reconnect_info', {
                'working_directory': full_working_directory,
                'pid': self.container.id,
                'pid_paths': {}}
            )

            context.update_state(JobStatus.State.RUNNING)
            logger.info(f"Docker container started ({self.docker_image_tag}) for job {context.job_id()}")

        except SaaSRuntimeException:
            raise
        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            raise DockerRuntimeError({
                'job': context.job().dict(),
                'wd_path': wd_path,
                'trace': trace
            })

    def monitor_job_execution(self, context: base.JobContext) -> None:
        # Retrieve container from descriptor if not found
        if self.container is None:
            with self.get_docker_client() as client:
                client: docker.DockerClient
                # FIXME: What happens if the job has completed successfully and container has already been removed.
                self.container = client.containers.get(context.get_note('reconnect_info')['pid'])
        try:
            # Will only continue monitoring if container is still running.
            # If container exited with a non-zero code, it means that an error has occurred instead of a lost connection
            if self.container.status == "exited":
                info = self.container.wait()
                if info.get('StatusCode') != 0:
                    raise SaaSRuntimeException

            # Block and go through logs until container closes
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = list()
                for log in self.container.logs(stream=True):
                    if context.state() == JobStatus.State.CANCELLED:
                        # cancel tasks that are not yet running
                        for future in futures:
                            future.cancel()

                        self.container.stop()
                        # wait till all running tasks to finish
                        executor.shutdown(wait=True)
                        break

                    lines = log.decode('utf-8').splitlines()

                    for line in lines:
                        if line.startswith('trigger:output'):
                            future = executor.submit(self._handle_trigger_output, line, context)
                            futures.append(future)

                        if line.startswith('trigger:progress'):
                            self._handle_trigger_progress(line, context)

                        if line.startswith('trigger:message'):
                            self._handle_trigger_message(line, context)

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            raise DockerRuntimeError({
                'job': context.job().dict(),
                'working_directory': context.get_note('reconnect_info')["working_directory"],
                'trace': trace
            })
        finally:
            # Remove container after job is done
            self.container.wait()
            self.container.remove()
            self.container = None

    def cancel_job_execution(self, context: base.JobContext) -> None:
        pass

    def delete(self) -> None:
        # FIXME: Might not be thread safe
        # Remove entry added to ssh config
        if self.using_remote:
            remove_host_from_ssh_config(self._proc_id)

    def _handle_trigger_output(self, line: str, context: base.JobContext) -> None:
        obj_name = line.split(':')[2]
        working_directory = context.get_note('reconnect_info')['working_directory']
        try:
            context.put_note(f"process_output:{obj_name}", 'started')

            if self.using_remote:
                # Fetch object from remote container
                context.put_note(f"process_output:{obj_name}", 'retrieve')
                remote_obj = f"{self.container_working_directory}/{obj_name}"
                data, stat = self.container.get_archive(remote_obj)
                datastream = generator_to_stream(data)
                with tarfile.open(fileobj=datastream, mode='r|*') as tf:
                    tf.extractall(working_directory)

            context.put_note(f"process_output:{obj_name}", 'push')
            self.push_data_object(obj_name, working_directory, context)
            context.put_note(f"process_output:{obj_name}", 'done')

        except SaaSRuntimeException as e:
            context.put_note(f"process_output:{obj_name}", 'failed')
            context.add_error(f"process_output:{obj_name} failed", ExceptionContent(id=e.id, reason=e.reason,
                                                                                    details=e.details))

    def _handle_trigger_progress(self, line: str, context: base.JobContext) -> None:
        """
        Line is in the format `trigger:progress:<int>`
        """
        progress = line.split(':')[2]
        context.update_progress(int(progress))

    def _handle_trigger_message(self, line: str, context: base.JobContext) -> None:
        """
        Line is in the format `trigger:message:<type:str>:<message:str>`
        """
        temp = line.split(':', 3)
        severity = temp[2]
        message = temp[3]
        context.update_message(severity, message)


def generator_to_stream(generator):
    """
    Receives a generator object and returns a file-like object based on it
    """
    class GeneratorStream(io.RawIOBase):
        def __init__(self):
            self.leftover = None

        def readable(self):
            return True

        def readinto(self, b):
            try:
                read_bytes = len(b)  # number of bytes to be read
                chunk = self.leftover or next(generator)
                output, self.leftover = chunk[:read_bytes], chunk[read_bytes:]
                b[:len(output)] = output
                return len(output)
            except StopIteration:
                return 0  # : Indicate EOF

    return io.BufferedReader(GeneratorStream())
