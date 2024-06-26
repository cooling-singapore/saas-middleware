from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import threading
import time
import traceback
from abc import abstractmethod, ABC
from enum import Enum
from threading import Lock, Thread
from typing import Optional, List, Dict, Union

import paramiko

from saas.core.exceptions import SaaSRuntimeException, ExceptionContent
from saas.core.helpers import decrypt_file, encrypt_file, hash_json_object
from saas.core.keypair import KeyPair
from saas.core.rsakeypair import RSAKeyPair
from saas.dor.proxy import DORProxy
from saas.core.helpers import read_json_from_file, write_json_to_file, validate_json, generate_random_string
from saas.core.logging import Logging
from saas.nodedb.exceptions import IdentityNotFoundError
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.nodedb.proxy import NodeDBProxy
from saas.p2p.exceptions import PeerUnavailableError
from saas.rest.exceptions import UnsuccessfulRequestError
from saas.rti.exceptions import ProcessorNotAcceptingJobsError, UnresolvedInputDataObjectsError, \
    AccessNotPermittedError, MissingUserSignatureError, MismatchingDataTypeOrFormatError, InvalidJSONDataObjectError, \
    DataObjectContentNotFoundError, DataObjectOwnerNotFoundError, RTIException, RunCommandError

from saas.rti.schemas import JobStatus, ProcessorStatus, Job
from saas.dor.schemas import GitProcessorPointer, DataObject, CDataObject
from saas.nodedb.schemas import NodeInfo
from saas.core.schemas import SSHCredentials

logger = Logging.get('rti.adapters')


def join_paths(components: List[str], ssh_credentials: SSHCredentials = None) -> str:
    unix_sep = '/'
    win_sep = '\\'

    if ssh_credentials:
        separators = (win_sep, unix_sep) if ssh_credentials.is_cygwin else (unix_sep, win_sep)
    else:
        separators = (win_sep, unix_sep) if os.path.sep == win_sep else (unix_sep, win_sep)

    result = separators[0].join(components)
    result = result.replace(separators[1], separators[0])
    result = result.replace(f'{separators[0]}{separators[0]}', separators[0])
    return result


def run_command(command: str, ssh_credentials: SSHCredentials = None, timeout: int = None,
                check_exitcode: bool = True, attempts: int = 10) -> subprocess.CompletedProcess:

    # wrap the command depending on whether it is to be executed locally or remote (if ssh credentials provided)
    if ssh_credentials:
        args = ['-i', ssh_credentials.key_path]
        if timeout:
            args.extend(['-o', f"ConnectTimeout={timeout}"])

        wrapped_command = ['ssh', *args, f"{ssh_credentials.login}@{ssh_credentials.host}", command]

    else:
        wrapped_command = ['bash', '-c', command]

    # try to execute the command
    error = None
    for attempt in range(attempts):
        try:
            result = subprocess.run(wrapped_command, capture_output=True, check=check_exitcode, timeout=timeout)
            return result

        except subprocess.CalledProcessError as e:
            error = {
                'reason': 'non-zero return code',
                'returncode': e.returncode,
                'wrapped_command': wrapped_command,
                'stdout': e.stdout.decode('utf-8'),
                'stderr': e.stderr.decode('utf-8'),
                'ssh_credentials_path': ssh_credentials.key_path if ssh_credentials else None
            }
            logger.error(f"[attempt:{(attempt+1)}/{attempts}] error: {error}")

        except subprocess.TimeoutExpired:
            error = {
                'reason': 'timeout',
                'wrapped_command': wrapped_command,
                'ssh_credentials_path': ssh_credentials.key_path if ssh_credentials else None
            }
            logger.error(f"[attempt:{(attempt+1)}/{attempts}] error: {error}")

        time.sleep(5)

    raise RunCommandError(error)


def scp_local_to_remote(local_path: str, remote_path: str, ssh_credentials: SSHCredentials) -> None:
    # generate the wrapped command
    wrapped_command = ['scp', '-i', ssh_credentials.key_path, local_path,
                       f"{ssh_credentials.login}@{ssh_credentials.host}:{remote_path}"]

    # execute command
    result = subprocess.run(wrapped_command, capture_output=True)
    if result.returncode != 0:
        raise RunCommandError({
            'wrapped_command': wrapped_command,
            'ssh_credentials_path': ssh_credentials.key_path,
            'result': result
        })


def scp_remote_to_local(remote_path: str, local_path: str, ssh_credentials: SSHCredentials) -> None:
    # generate the wrapped command
    wrapped_command = ['scp', '-i', ssh_credentials.key_path,
                       f"{ssh_credentials.login}@{ssh_credentials.host}:{remote_path}", local_path]

    # execute command
    result = subprocess.run(wrapped_command, capture_output=True)
    if result.returncode != 0:
        raise RunCommandError({
            'wrapped_command': wrapped_command,
            'ssh_credentials_path': ssh_credentials.key_path,
            'result': result
        })


def determine_home_path(ssh_credentials: SSHCredentials = None) -> str:
    result = run_command('echo ~', ssh_credentials)
    home = result.stdout.decode('utf-8')
    home = home.strip()

    if home.startswith("/cygdrive/"):  # fix path for Windows machine with cygwin
        home = home.replace("/cygdrive/", "")
        home = f"{home[:1]}:{home[1:]}"

    return home


def determine_if_cygwin(ssh_credentials: SSHCredentials) -> bool:
    result = run_command("uname", ssh_credentials=ssh_credentials)
    env = result.stdout.decode('utf-8').strip()
    return "cygwin" in env.lower()


def get_pid(pid_path: str, ssh_credentials: SSHCredentials = None, max_attempts: int = 10) -> str:
    for attempt in range(max_attempts):
        command = f'if [ -e "{pid_path}" ]; then cat {pid_path}; else echo -1; fi'
        result = run_command(command, ssh_credentials=ssh_credentials, timeout=10)
        temp = result.stdout.decode('utf-8').splitlines()
        if temp is None or len(temp) == 0 or temp[0] == '-1':
            logger.debug(f"PID file content at '{pid_path}' does not contain PID (content: {temp})... "
                         f"try again (attempt={attempt+1}/{max_attempts})")
            time.sleep(0.5)
            continue

        # return the PID
        return temp[0]

    raise RunCommandError(reason='Failed to obtain PID', details={'pid_path': pid_path})


def run_command_async(command: str, local_output_path: str, name: str,
                      ssh_credentials: SSHCredentials = None) -> (str, dict):

    paths = {
        'local_wd_path': local_output_path,
        'local_stdout': os.path.join(local_output_path, f"{name}.stdout"),
        'local_stderr': os.path.join(local_output_path, f"{name}.stderr"),
        'local_pid': os.path.join(local_output_path, f"{name}.pid"),
        'local_exitcode': os.path.join(local_output_path, f"{name}.exitcode"),
        'local_script': os.path.join(local_output_path, f"{name}.sh")
    }

    # make sure the local working directory exists
    if not os.path.isdir(paths['local_wd_path']):
        os.makedirs(paths['local_wd_path'])

    if ssh_credentials is not None:
        remote_output_path = ssh_credentials.home_path + local_output_path.replace(os.environ['HOME'], '')
        paths['remote_wd_path'] = remote_output_path
        paths['remote_stdout'] = join_paths([remote_output_path, f"{name}.stdout"], ssh_credentials)
        paths['remote_stderr'] = join_paths([remote_output_path, f"{name}.stderr"], ssh_credentials)
        paths['remote_pid'] = join_paths([remote_output_path, f"{name}.pid"], ssh_credentials)
        paths['remote_exitcode'] = join_paths([remote_output_path, f"{name}.exitcode"], ssh_credentials)
        paths['remote_script'] = join_paths([remote_output_path, f"{name}.sh"], ssh_credentials)

        paths['wd_path'] = paths['remote_wd_path']
        paths['stdout'] = paths['remote_stdout']
        paths['stderr'] = paths['remote_stderr']
        paths['pid'] = paths['remote_pid']
        paths['script'] = paths['remote_script']
        paths['exitcode'] = paths['remote_exitcode']

    else:
        paths['wd_path'] = paths['local_wd_path']
        paths['stdout'] = paths['local_stdout']
        paths['stderr'] = paths['local_stderr']
        paths['pid'] = paths['local_pid']
        paths['script'] = paths['local_script']
        paths['exitcode'] = paths['local_exitcode']

    # we are going to chain together a number of commands to avoid having to run many commands
    chain_command = ''

    # 1) ensure the working directory exists
    chain_command += f"mkdir -p {paths['wd_path']}"

    # 2) echo the contents of the wrapper script
    chain_command += ' && echo -e "#!/bin/bash\n' \
                     f'touch {paths["stdout"]}\n' \
                     f'touch {paths["stderr"]}\n' \
                     f'touch {paths["exitcode"]}\n' \
                     f'{command} > {paths["stdout"]} 2> {paths["stderr"]} &\n' \
                     f'pid=\$!\n' \
                     f'echo \$pid > {paths["pid"]}\n' \
                     f'wait \$pid\n' \
                     f'echo \$? > {paths["exitcode"]}" > {paths["script"]}'

    # 3) make the wrapper script executable
    chain_command += f" && chmod u+x {paths['script']}"

    # execute the chain command
    run_command(chain_command, ssh_credentials=ssh_credentials, timeout=10)

    # execute the wrapper script
    if ssh_credentials and ssh_credentials.is_cygwin:
        # nohup does not really work in cygwin
        command = f"cygstart {paths['script']}"
    else:
        command = f"nohup {paths['script']} > /dev/null 2>&1 &"
    run_command(command, ssh_credentials=ssh_credentials, timeout=10)

    # get the PID
    pid = get_pid(paths['pid'], ssh_credentials=ssh_credentials)
    logger.info(f"started async process {pid} running {'REMOTE:' if ssh_credentials else 'LOCAL:'}{paths['script']}")

    return pid, paths


def monitor_command(pid: str, pid_paths: dict[str, str], triggers: dict = None, ssh_credentials: SSHCredentials = None,
                    context: JobContext = None) -> None:

    job_id = context.job_id() if context else '...'
    logger.info(f"[job:{job_id}] begin monitoring {'REMOTE' if ssh_credentials else 'LOCAL'}:{pid}...")

    class Session:
        def __init__(self):
            self.exitcode = None
            self.ssh_client = None

            if ssh_credentials:
                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                private_key = paramiko.RSAKey.from_private_key_file(ssh_credentials.key_path)
                self.ssh_client.connect(ssh_credentials.host, username=ssh_credentials.login, pkey=private_key)

    def wait_for_exitcode_local(session: Session) -> None:
        while session.exitcode is None:
            time.sleep(2.5)
            if os.path.isfile(pid_paths['exitcode']) and os.path.getsize(pid_paths['exitcode']) > 0:
                with open(pid_paths['exitcode'], 'r') as f:
                    content = f.read()
                    content = content.strip()
                    session.exitcode = int(content)
                    break

    def wait_for_exitcode_remote(session: Session) -> None:
        sftp = session.ssh_client.open_sftp()
        while session.exitcode is None:
            time.sleep(2.5)
            file_info = sftp.stat(pid_paths['exitcode'])
            if file_info.st_size > 0:
                with sftp.file(pid_paths['exitcode'], 'r') as f:
                    content = f.read()
                    session.exitcode = int(content)
                    break

        sftp.close()

    def monitor_stdout_local(session: Session) -> None:
        position = 0
        while session.exitcode is None:
            time.sleep(1)
            with open(pid_paths['stdout'], 'r') as f:
                f.seek(position)
                for line in f:
                    line = line.rstrip('\n')  # Remove newline character
                    for pattern, info in triggers.items():
                        if pattern in line:
                            idx = line.index(pattern)
                            line = line[idx:]
                            info['func'](line, info['context'])

                position = f.tell()

    def parse_buffer(buffer: str, addition: str) -> str:
        # add on to the buffer and split into lines (if any)
        buffer += addition
        temp = buffer.split('\n')

        # process lines and see if any triggers match -> last 'line' is unfinished buffer
        for line in temp[:-1]:
            for pattern, info in triggers.items():
                if pattern in line:
                    idx = line.index(pattern)
                    line = line[idx:]
                    info['func'](line, info['context'])

        return temp[-1]

    def monitor_stdout_remote(session: Session) -> None:
        ssh_shell = session.ssh_client.invoke_shell()
        ssh_shell.send(f"tail -f {pid_paths['stdout']}\n".encode('utf-8'))
        buffer = ''
        while session.exitcode is None:
            # read whatever is there to read and parse it
            if ssh_shell.recv_ready():
                received = ssh_shell.recv(4096).decode('utf-8').replace('\r', '')
                buffer = parse_buffer(buffer, received)

            else:
                time.sleep(0.5)

        # wait for stdout/stderr files to no longer change
        sftp = session.ssh_client.open_sftp()
        stdout_size = sftp.stat(pid_paths['remote_stdout']).st_size
        stderr_size = sftp.stat(pid_paths['remote_stderr']).st_size
        while True:
            time.sleep(1)
            new_stdout_size = sftp.stat(pid_paths['remote_stdout']).st_size
            new_stderr_size = sftp.stat(pid_paths['remote_stderr']).st_size

            if new_stdout_size == stdout_size and new_stderr_size == stderr_size:
                break
            else:
                stdout_size = new_stdout_size
                stderr_size = new_stderr_size

        # read whatever is there to read and parse it
        while ssh_shell.recv_ready():
            if ssh_shell.recv_ready():
                received = ssh_shell.recv(4096).decode('utf-8').replace('\r', '')
                buffer = parse_buffer(buffer, received)

        # copy remote files to local
        sftp.get(pid_paths['remote_stdout'], pid_paths['local_stdout'])
        sftp.get(pid_paths['remote_stderr'], pid_paths['local_stderr'])
        sftp.get(pid_paths['remote_exitcode'], pid_paths['local_exitcode'])

        ssh_shell.close()
        sftp.close()

    def wait_for_cancellation_local(session: Session) -> None:
        while session.exitcode is None:
            time.sleep(1)
            if context.state() == JobStatus.State.CANCELLED:
                os.kill(int(pid), signal.SIGKILL)

                session.exitcode = -9
                break

    def wait_for_cancellation_remote(session: Session) -> None:
        while session.exitcode is None:
            time.sleep(1)
            if context.state() == JobStatus.State.CANCELLED:
                ssh_shell = session.ssh_client.invoke_shell()
                ssh_shell.send(f"kill -9 {pid}".encode('utf-8'))
                ssh_shell.close()

                session.exitcode = -9
                break

    # what functions to run?
    functions = [wait_for_exitcode_remote if ssh_credentials else wait_for_exitcode_local]
    if context:
        functions.append(wait_for_cancellation_remote if ssh_credentials else wait_for_cancellation_local)
    if triggers:
        functions.append(monitor_stdout_remote if ssh_credentials else monitor_stdout_local)

    # create threads and start them
    session = Session()
    threads = []
    for f in functions:
        t = threading.Thread(target=f, kwargs={'session': session})
        t.start()
        threads.append(t)

    # wait for all threads to be done
    for t in threads:
        t.join()


def check_if_path_exists(path: str, ssh_credentials: SSHCredentials = None, timeout: int = None) -> bool:
    result = run_command(f"ls {path}", ssh_credentials=ssh_credentials, timeout=timeout, check_exitcode=False)
    return result.returncode == 0


def create_symbolic_link(link_path: str, target_path: str, working_directory: str = None) -> None:
    if working_directory:
        link_path = os.path.join(working_directory, link_path)
        target_path = os.path.join(working_directory, target_path)

    os.symlink(src=target_path, dst=link_path)
    # run_command(f"ln -sf {target_path} {link_path}")


class JobRunner(Thread):
    def __init__(self, owner: RTIProcessorAdapter, context: JobContext):
        super().__init__(name=f"job_runner.{context.job_id()}")
        self._owner = owner
        self._context = context

    @property
    def job(self) -> Job:
        return self._context.job()

    def cancel(self) -> None:
        logger.info(f"[job:{self._context.job_id()}:{self._context.state().value}] cancel job!")
        self._context.update_state(JobStatus.State.CANCELLED)
        self._owner.cancel_job_execution(self._context)

    def run(self):
        # get a few things for convenience
        context = self._context
        job_id = context.job().id
        wd_path = context.wd_path()

        # is the job still uninitialised?
        if context.state() == JobStatus.State.UNINITIALISED:
            try:
                # perform pre-execution routine
                self._owner.pre_execute(wd_path, self._context)

            except SaaSRuntimeException as e:
                context.add_error(e.reason, e.content)
                state = context.update_state(JobStatus.State.FAILED)
                logger.warning(
                    f"[job:{job_id}:{state.value}] monitoring execution failed: [{e.id}] {e.reason} {e.details}")

            except Exception as e:
                state = context.update_state(JobStatus.State.FAILED)
                trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
                logger.error(f"[job:{job_id}:{state.value}] initialisation failed: {e}\n{trace}")

            else:
                state = context.update_state(JobStatus.State.INITIALISED)
                logger.info(f"[job:{job_id}:{state.value}] initialisation successful")

        # is the job initialised?
        if context.state() == JobStatus.State.INITIALISED:
            try:
                # instruct the adapter to execute the job
                self._owner.begin_job_execution(wd_path, self._context)

            except SaaSRuntimeException as e:
                context.add_error(e.reason, e.content)
                state = context.update_state(JobStatus.State.FAILED)
                logger.warning(
                    f"[job:{job_id}:{state.value}] monitoring execution failed: [{e.id}] {e.reason} {e.details}")

            except Exception as e:
                state = context.update_state(JobStatus.State.FAILED)
                trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
                logger.error(f"[job:{job_id}:{state.value}] triggering execution failed: {e}\n{trace}")

        # is the job running?
        if context.state() == JobStatus.State.RUNNING:
            while True:
                try:
                    # connect to the job and monitor its progress
                    self._owner.monitor_job_execution(self._context)

                except UnsuccessfulRequestError as e:
                    # this could be due to some timing issues, just try again to monitor the job
                    state = context.state()
                    logger.warning(
                        f"[job:{job_id}:{state.value}] monitoring execution failed: [{e.id}] {e.reason} {e.details} -> "
                        f"trying again in 1 second.")

                    time.sleep(1)
                    continue

                except SaaSRuntimeException as e:
                    context.add_error(e.reason, e.content)
                    state = context.update_state(JobStatus.State.FAILED)
                    logger.error(
                        f"[job:{job_id}:{state.value}] monitoring execution failed: [{e.id}] {e.reason} {e.details}")
                    break

                except Exception as e:
                    state = context.update_state(JobStatus.State.FAILED)
                    trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
                    logger.error(f"[job:{job_id}:{state.value}] monitoring execution failed: {e}\n{trace}")
                    break

                else:
                    state = context.update_state(JobStatus.State.POSTPROCESSING)
                    logger.info(f"[job:{job_id}:{state.value}] monitoring execution successful")
                    break

            # is the job running?
            if context.state() == JobStatus.State.POSTPROCESSING:
                try:
                    # perform post-execution routine
                    self._owner.post_execute(job_id)

                except SaaSRuntimeException as e:
                    context.add_error(e.reason, e.content)
                    state = context.update_state(JobStatus.State.FAILED)
                    logger.warning(
                        f"[job:{job_id}:{state.value}] monitoring execution failed: [{e.id}] {e.reason} {e.details}")

                except Exception as e:
                    state = context.update_state(JobStatus.State.FAILED)
                    trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
                    logger.error(f"[job:{job_id}:{state.value}] post-execution routine failed: {e}\n{trace}")

                else:
                    state = context.update_state(JobStatus.State.SUCCESSFUL)
                    logger.info(f"[job:{job_id}:{state.value}] post-execution routine successful")

            # if the job history is not to be retained, delete its contents (with exception to the status and
            # the job descriptor)
            if not context.job().retain:
                exclusions = ['job_descriptor.json', 'job_status.json', 'execute_sh.stderr', 'execute_sh.stdout',
                              'execute_sh.pid', 'execute.sh']
                logger.info(f"[job:{job_id}] deleting working directory contents at {wd_path} "
                            f"(exclusions: {exclusions})...")

                # delete the file/dir/link unless it's in the exclusion list
                for item in os.listdir(wd_path):
                    if not item.endswith(tuple(exclusions)):
                        path = os.path.join(wd_path, item)
                        if os.path.isfile(path):
                            os.remove(path)
                        elif os.path.isdir(path):
                            shutil.rmtree(path)
                        elif os.path.islink(path):
                            os.unlink(path)
                        else:
                            logger.warning(f"Encountered neither file nor directory: {path}")

        # remove the job from the active set
        self._owner.pop_job_runner(job_id)


class ProcessorState(str, Enum):
    UNINITIALISED = 'uninitialised'
    STARTING = 'starting'
    OPERATIONAL = 'operational'
    STOPPING = 'stopping'
    STOPPED = 'stopped'
    FAILED = 'failed'


class ProcessorStateWrapper(ABC):
    @abstractmethod
    def state(self) -> ProcessorState:
        pass

    @abstractmethod
    def update_state(self, state: ProcessorState) -> ProcessorState:
        pass

    @abstractmethod
    def delete(self) -> None:
        pass


class JobContext(ABC):
    @abstractmethod
    def job_id(self) -> str:
        pass

    @abstractmethod
    def job(self) -> Job:
        pass

    @abstractmethod
    def wd_path(self) -> str:
        pass

    @abstractmethod
    def descriptor_path(self) -> str:
        pass

    @abstractmethod
    def state(self) -> JobStatus.State:
        pass

    @abstractmethod
    def update_state(self, new_state: JobStatus.State) -> JobStatus.State:
        pass

    @abstractmethod
    def status(self) -> JobStatus:
        pass

    @abstractmethod
    def add_pending_output(self, obj_name: str) -> None:
        pass

    @abstractmethod
    def get_pending_outputs(self) -> List[str]:
        pass

    @abstractmethod
    def pop_pending_output(self, obj_name: str, obj: CDataObject) -> str:
        pass

    @abstractmethod
    def progress(self) -> int:
        pass

    @abstractmethod
    def update_progress(self, new_progress: int) -> int:
        pass

    @abstractmethod
    def update_message(self, severity: str, message: str) -> None:
        pass

    @abstractmethod
    def put_note(self, key: str, note: Union[str, int, float, bool, dict, list]) -> None:
        pass

    @abstractmethod
    def get_note(self, key: str, default: Union[str, int, float, bool, dict, list] = None) -> Union[str, int, float,
                                                                                                    bool, dict, list]:
        pass

    @abstractmethod
    def remove_note(self, key: str) -> None:
        pass

    @abstractmethod
    def add_error(self, message: str, exception: ExceptionContent) -> None:
        pass

    @abstractmethod
    def errors(self) -> List[JobStatus.Error]:
        pass


def shorten_id(long_id: str) -> str:
    return long_id[:4] + '...' + long_id[-4:]


class RTIProcessorAdapter(Thread, ABC):
    def __init__(self, proc_id: str, gpp: GitProcessorPointer, db_wrapper: ProcessorStateWrapper,
                 node, job_wd_path: str, job_concurrency: bool) -> None:
        Thread.__init__(self, daemon=True, name=f"rti.adapter:{proc_id[0:8]}...")

        self._mutex = Lock()
        self._proc_id = proc_id
        self._proc_short_id = shorten_id(proc_id)
        self._gpp = gpp
        self._db_wrapper = db_wrapper
        self._node = node
        self._job_wd_path = job_wd_path
        self._job_concurrency = job_concurrency
        self._stop_signal_received = False

        self._input_interface = {item.name: item for item in gpp.proc_descriptor.input}
        self._output_interface = {item.name: item for item in gpp.proc_descriptor.output}
        self._pending: List[JobContext] = []
        self._active: Dict[str, JobRunner] = {}

    @property
    def id(self) -> str:
        return self._proc_id

    @property
    def short_id(self) -> str:
        return self._proc_short_id

    @property
    def gpp(self) -> GitProcessorPointer:
        return self._gpp

    @property
    def state(self) -> ProcessorState:
        return self._db_wrapper.state()

    @abstractmethod
    def startup(self) -> None:
        pass

    @abstractmethod
    def shutdown(self) -> None:
        pass

    @abstractmethod
    def begin_job_execution(self, wd_path: str, context: JobContext) -> None:
        pass

    @abstractmethod
    def monitor_job_execution(self, context: JobContext) -> None:
        pass

    @abstractmethod
    def cancel_job_execution(self, context: JobContext) -> None:
        pass

    def run(self) -> None:
        def update_state(new_state: ProcessorState) -> ProcessorState:
            with self._mutex:
                return self._db_wrapper.update_state(new_state)

        # get the current state
        state = self._db_wrapper.state()

        # uninitialised? do startup...
        if state in [ProcessorState.UNINITIALISED, ProcessorState.STARTING]:
            if state == ProcessorState.STARTING:
                logger.warning(f"[adapter:{self._proc_short_id}:{state.value}] appears to have been interrupted "
                               f"while performing startup routine. trying again...")
            else:
                logger.info(f"[adapter:{self._proc_short_id}:{state.value}] performing startup routine...")

            try:
                update_state(ProcessorState.STARTING)
                self.startup()

            except SaaSRuntimeException as e:
                state = update_state(ProcessorState.FAILED)
                logger.error(
                    f"[adapter:{self._proc_short_id}:{state.value}] start-up failed: [{e.id}] {e.reason} {e.details}")

            except Exception as e:
                state = update_state(ProcessorState.FAILED)
                trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
                logger.error(f"[adapter:{self._proc_short_id}:{state.value}] start-up failed: {e}\n{trace}")

            else:
                state = update_state(ProcessorState.OPERATIONAL)
                logger.info(f"[adapter:{self._proc_short_id}:{state.value}] has started up.")

        # while the processor is not stopped, and there are pending jobs, execute them
        # (either in sequence or concurrently)
        while state == ProcessorState.OPERATIONAL:
            # get the latest state from the db to check if we are still operational
            state = self._db_wrapper.state()
            if state != ProcessorState.OPERATIONAL:
                break

            try:
                # can we add a job? do we have a job?
                if (self._job_concurrency or len(self._active) == 0) and len(self._pending) > 0:
                    # get the job
                    with self._mutex:
                        context = self._pending.pop(0)

                        # create a job runner
                        runner = JobRunner(self, context)
                        self._active[context.job_id()] = runner

                    # start the job runner
                    logger.info(f"[adapter:{self._proc_short_id}:{state.value}] starting job runner "
                                f"for {runner.job.id}:{context.job().proc_name}.")
                    runner.start()

                    # try if there is another job pending right away
                    continue

                else:
                    # wait a bit...
                    time.sleep(1.0)

            except SaaSRuntimeException as e:
                state = update_state(ProcessorState.FAILED)
                logger.error(
                    f"[adapter:{self._proc_short_id}:{state.value}] processing jobs failed: "
                    f"[{e.id}] {e.reason} {e.details}")

            except Exception as e:
                state = update_state(ProcessorState.FAILED)
                trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
                logger.error(f"[adapter:{self._proc_short_id}:{state.value}] processing jobs failed: {e}\n{trace}")

        if state == ProcessorState.STOPPING:
            # purge jobs before shutting down
            with self._mutex:
                for job_type, context in self._pending:
                    logger.info(
                        f"[adapter:{self._proc_short_id}:{state.value}] purged pending job: "
                        f"{job_type} {context.status.job}"
                    )
                self._pending = []

                for job_id, runner in self._active.items():
                    runner.cancel()
                    logger.info(f"[adapter:{self._proc_short_id}:{state.value}] purged active job: {runner.job}")
                self._active = {}

            logger.info(f"[adapter:{self._proc_short_id}:{state.value}] performing shutdown routine...")
            self.shutdown()

            state = update_state(ProcessorState.STOPPED)
            logger.info(f"[adapter:{self._proc_short_id}:{state.value}] has stopped.")

            # delete the processor
            logger.info(f"[adapter:{self._proc_short_id}] deleting processor..")
            self.delete()

            # delete the db record
            logger.info(f"[adapter:{self._proc_short_id}] deleting DB record...")
            self._db_wrapper.delete()

    @abstractmethod
    def delete(self) -> None:
        pass

    def status(self) -> ProcessorStatus:
        with self._mutex:
            return ProcessorStatus(
                state=str(self._db_wrapper.state().value),
                pending=[context.job() for context in self._pending],
                active=[runner.job for _, runner in self._active.items()]
            )

    def pre_execute(self, working_directory: str, context: JobContext) -> None:
        logger.info(f"[adapter:{self._proc_short_id}:{self.state.value}] "
                    f"[job:{shorten_id(context.job().id)}] performing pre-execution routine...")

        # store by-value input data objects (if any)
        self._store_value_input_data_objects(working_directory, context)

        # lookup by-reference input data objects (if any)
        obj_records = self._lookup_reference_input_data_objects(context)

        # fetch by-reference input data objects (if any)
        ephemeral_key = RSAKeyPair.create_new()
        pending_content_keys = self._fetch_reference_input_data_objects(ephemeral_key, obj_records,
                                                                        working_directory, context)

        # decrypt by-reference input data objects (if any)
        self._decrypt_reference_input_data_objects(ephemeral_key, pending_content_keys, context)

        # verify that data types of input data objects match
        self._verify_inputs(working_directory, context)

        # verify the output owner identities
        self._verify_outputs(context)

    def post_execute(self, job_id: str) -> None:
        logger.info(f"[adapter:{self._proc_short_id}:{self.state.value}] "
                    f"[job:{shorten_id(job_id)}] performing post-execution routine...")

    def add(self, context: JobContext) -> None:
        with self._mutex:
            # are we accepting jobs?
            if self.state in [ProcessorState.STOPPING, ProcessorState.STOPPED]:
                raise ProcessorNotAcceptingJobsError({
                    'proc_id': self._proc_id,
                    'job': context.job().dict()
                })

            # create working directory (if it doesn't already exist)
            if not os.path.exists(context.wd_path()):
                os.makedirs(context.wd_path(), exist_ok=True)

            # write the job descriptor  (if it doesn't already exist)
            if not os.path.isfile(context.descriptor_path()):
                with open(context.descriptor_path(), 'w') as f:
                    f.write(json.dumps(context.job().dict(), indent=4))

            # add the job to the pending queue
            self._pending.append(context)

    def pending_jobs(self) -> List[Job]:
        with self._mutex:
            return [job_state.job() for job_state in self._pending]

    def active_jobs(self) -> List[Job]:
        with self._mutex:
            return [runner.job for _, runner in self._active.items()]

    def pop_job_runner(self, job_id: str) -> Optional[JobRunner]:
        with self._mutex:
            runner = self._active.pop(job_id) if job_id in self._active else None
            return runner

    def _lookup_reference_input_data_objects(self, context: JobContext) -> dict:
        context.put_note('step', "lookup by-reference input data objects")

        # do we have any by-reference input data objects in the first place?
        pending = {item.obj_id: item.user_signature if item.user_signature else None
                   for item in context.job().task.input if item.type == 'reference'}
        if len(pending) == 0:
            return {}

        # get the user identity
        user = self._node.db.get_identity(context.job().task.user_iid)
        if user is None:
            raise IdentityNotFoundError(context.job().task.user_iid)

        # lookup all referenced data objects using the P2P protocol
        protocol = DataObjectRepositoryP2PProtocol(self._node)
        found = {}
        for peer in self._node.db.get_network():
            # only check with peers that have a DOR
            if peer.dor_service:
                try:
                    # does the remote DOR have the data object?
                    response = protocol.lookup(peer.p2p_address, [*pending.keys()])
                    for obj_id, record in response.items():
                        found[obj_id] = record
                        found[obj_id]['custodian'] = peer
                        found[obj_id]['user_signature'] = pending[obj_id]
                        pending.pop(obj_id)

                    # still pending object ids? if not, we are done.
                    if len(pending) == 0:
                        break

                # ignore peers that are not available
                except PeerUnavailableError:
                    continue

        # do we still have pending data objects?
        if len(pending) > 0:
            raise UnresolvedInputDataObjectsError({
                'pending': pending,
                'found': found
            })

        # check if the user has access permissions and if we have user signatures for all restricted data objects
        for obj_id, item in found.items():
            if item['access_restricted']:
                if user.id not in item['access']:
                    raise AccessNotPermittedError({
                        'obj_id': obj_id,
                        'user_iid': user.id
                    })

                if 'user_signature' not in item:
                    raise MissingUserSignatureError({
                        'obj_id': obj_id,
                        'user_iid': user.id
                    })

        context.remove_note('step')
        return found

    def _fetch_reference_input_data_objects(self, ephemeral_key: KeyPair, obj_records: dict, working_directory: str,
                                            context: JobContext) -> list[dict]:

        context.put_note('step', "fetch by-reference input data objects")

        # do we have any data objects to fetch to begin with?
        if len(obj_records) == 0:
            context.remove_note('step')
            return []

        # get the user identity
        user = self._node.db.get_identity(context.job().task.user_iid)
        if user is None:
            raise IdentityNotFoundError(context.job().task.user_iid)

        # fetch input data objects one by one using the P2P protocol
        protocol = DataObjectRepositoryP2PProtocol(self._node)
        pending_content_keys = []
        c_hashes = {}
        for obj_id, record in obj_records.items():
            meta_path = os.path.join(working_directory, f"{obj_id}.meta")
            content_path = os.path.join(working_directory, f"{obj_id}.content")

            # fetch the data object
            custodian: NodeInfo = record['custodian']
            protocol.fetch(custodian.p2p_address, obj_id, meta_path, content_path,
                           context.job().task.user_iid if record['access_restricted'] else None,
                           record['user_signature'] if record['access_restricted'] else None)

            # obtain the content hash for this data object
            meta = read_json_from_file(meta_path)
            c_hashes[obj_id] = meta['c_hash']

            # is the data object content encrypted? if yes, then we need to request the content key
            if record['content_encrypted']:
                # get the owner identity
                owner = self._node.db.get_identity(record['owner_iid'])
                if owner is None:
                    raise IdentityNotFoundError(record['owner_iid'])

                # create the request content and encrypt it using the owners key
                req_id = generate_random_string(16)
                request = json.dumps({
                    'type': 'request_content_key',
                    'req_id': req_id,
                    'obj_id': obj_id,
                    'ephemeral_public_key': ephemeral_key.public_as_string(),
                    'user_iid': user.id,
                    'node_id': self._node.identity.id
                })
                request = owner.encrypt(request.encode('utf-8')).decode('utf-8')

                # publish the request
                # TODO: this should eventually be replaced by a proper event notification interface
                requests = context.get_note('requests', default=[])
                requests.append({
                    'req_id': req_id,
                    'receiver': user.id,
                    'request': request
                })
                context.put_note('requests', requests)

                # add on to the list of pending items
                pending_content_keys.append({
                    'req_id': req_id,
                    'obj_id': obj_id,
                    'path': content_path
                })

        # create symbolic links to the contents for every input AND update references with c_hash
        for item in context.job().task.input:
            if item.type == 'reference':
                create_symbolic_link(item.name, f"{item.obj_id}.content",
                                     working_directory=working_directory)

                create_symbolic_link(f"{item.name}.meta", f"{item.obj_id}.meta",
                                     working_directory=working_directory)

                item.c_hash = c_hashes[item.obj_id]

        context.remove_note('step')
        return pending_content_keys

    def _decrypt_reference_input_data_objects(self, ephemeral_key: KeyPair, pending_content_keys: list[dict],
                                              context: JobContext) -> None:
        context.put_note('step', "decrypt by-reference input data objects")
        while len(pending_content_keys) > 0:
            need_sleep = True
            for item in pending_content_keys:
                # have we received the permission for this request?
                permission = self._node.rti.pop_permission(item['req_id'])
                if permission is not None:
                    need_sleep = False

                    # decrypt the content key
                    content_key = ephemeral_key.decrypt(permission.encode('utf-8'), base64_encoded=True)

                    # decrypt the data object using the
                    decrypt_file(item['path'], content_key)

                    pending_content_keys.remove(item)
                    break

            if need_sleep:
                time.sleep(1)
        context.remove_note('step')

    def _store_value_input_data_objects(self, working_directory: str, context: JobContext) -> None:
        context.put_note('step', "store by-value input data objects")
        for item in context.job().task.input:
            # if it is a 'value' input then store it to the working directory
            if item.type == 'value':
                input_content_path = os.path.join(working_directory, item.name)
                write_json_to_file(item.value, input_content_path)
                write_json_to_file({
                    # data type can be anything (it's application specific). assuming 'JSONObject' as data type is
                    # not a good idea. instead, use the data type indicated in the input interface of the processor.
                    # however, what about the format? only json data is allowed to be used for 'by-value' input
                    # data objects. so hard-coding 'json' has data format seems justified. if the processor expects
                    # a different format, then this will raise a MismatchingDataTypeOrFormatError exception.
                    'data_type': self._input_interface[item.name].data_type,
                    'data_format': 'json'
                }, f"{input_content_path}.meta")
        context.remove_note('step')

    def _verify_inputs(self, working_directory: str, context: JobContext) -> None:
        context.put_note('step', 'verify inputs: data object types and formats')
        for item in context.job().task.input:
            obj_name = item.name

            # check if data type/format indicated in processor descriptor and data object descriptor match
            d0 = read_json_from_file(os.path.join(working_directory, f"{obj_name}.meta"))
            d1 = self._input_interface[obj_name]
            if d0['data_type'] != d1.data_type or d0['data_format'] != d1.data_format:
                raise MismatchingDataTypeOrFormatError({
                    'obj_name': obj_name,
                    'expected': {
                        'data_type': d1.data_type,
                        'data_format': d1.data_format
                    },
                    'actual': {
                        'data_type': d0['data_type'],
                        'data_format': d0['data_format']
                    }
                })

            # in case of JSONObject data type, verify using the schema (if any)
            if d0['data_type'] == 'JSONObject' and 'schema' in d1:
                content = read_json_from_file(os.path.join(working_directory, obj_name))
                if not validate_json(content, d1['schema']):
                    raise InvalidJSONDataObjectError({
                        'obj_name': obj_name,
                        'content': content,
                        'schema': d1['schema']
                    })
        context.remove_note('step')

    def _verify_outputs(self, context: JobContext) -> None:
        context.put_note('step', 'verify outputs: data object owner identities')
        for item in context.job().task.output:
            owner = self._node.db.get_identity(item.owner_iid)
            if owner is None:
                raise DataObjectOwnerNotFoundError({
                    'output_name': item.name,
                    'owner_iid': item.owner_iid
                })
        context.remove_note('step')

    def push_data_object(self, obj_name: str, wd_path: str, context: JobContext) -> None:
        # convenience variables
        task_out_items = {item.name: item for item in context.job().task.output}
        task_out = task_out_items[obj_name]
        proc_out = self._output_interface[obj_name]

        # check if the output data object exists
        output_content_path = os.path.join(wd_path, obj_name)
        if not os.path.isfile(output_content_path):
            raise DataObjectContentNotFoundError({
                'output_name': obj_name,
                'content_path': output_content_path
            })

        # get the owner
        owner = self._node.db.get_identity(task_out.owner_iid, raise_if_unknown=False)
        if owner is None:
            raise DataObjectOwnerNotFoundError({
                'output_name': obj_name,
                'owner_iid': task_out.owner_iid
            })

        # is the output a JSONObject?
        if proc_out.data_type == 'JSONObject' and 'schema' in proc_out:
            content = read_json_from_file(output_content_path)
            if not validate_json(content, proc_out.schema):
                raise InvalidJSONDataObjectError({
                    'obj_name': obj_name,
                    'content': content,
                    'schema': proc_out.schema
                })

        restricted_access = task_out.restricted_access
        content_encrypted = task_out.content_encrypted

        # TODO: figure out what is supposed to happen with the content key here
        encrypt_file(output_content_path, encrypt_for=owner, delete_source=True) if content_encrypted else None

        # do we have a target node specified for storing the data object?
        target_address = self._node.rest.address()
        if task_out.target_node_iid:
            # check with the node db to see if we know about this node
            network = {item.identity.id: item for item in self._node.db.get_network()}
            if task_out.target_node_iid not in network:
                raise RTIException("Target node not found in network", details={
                    'target_node_iid': task_out.target_node_iid,
                    'network': network
                })

            # extract the rest address from that node record
            node = network[task_out.target_node_iid]
            target_address = node.rest_address

        # check if the target node has DOR capabilities
        proxy = NodeDBProxy(target_address)
        node = proxy.get_node()
        if not node.dor_service:
            raise RTIException("Target node does not support DOR capabilities", details={
                'target_address': target_address,
                'node': node.dict()
            })

        # determine recipe
        recipe = {
            'name': obj_name,
            'processor': self._gpp.dict(),
            'consumes': {},
            'product': {
                'c_hash': '',  # valid content hash will be set by the DOR
                'data_type': proc_out.data_type,
                'data_format': proc_out.data_format
            }
        }

        # update recipe inputs
        for item0 in context.job().task.input:
            spec = self._input_interface[item0.name]
            if item0.type == 'value':
                recipe['consumes'][item0.name] = {
                    'c_hash': hash_json_object(item0.value).hex(),
                    'data_type': spec.data_type,
                    'data_format': spec.data_format,
                    'content': item0.value
                }
            else:
                recipe['consumes'][item0.name] = {
                    'c_hash': item0.c_hash,
                    'data_type': spec.data_type,
                    'data_format': spec.data_format,
                }

        # upload the data object to the DOR (the owner is the node for now
        # so we can update tags in the next step)
        proxy = DORProxy(target_address)
        obj = proxy.add_data_object(output_content_path, self._node.identity, restricted_access, content_encrypted,
                                    proc_out.data_type, proc_out.data_format, recipe=recipe)

        # update tags with information from the job
        obj = proxy.update_tags(obj.obj_id, self._node.keystore, [
            DataObject.Tag(key='name', value=obj_name),
            DataObject.Tag(key='job_id', value=context.job().id)
        ])

        # transfer ownership to the new owner
        obj = proxy.transfer_ownership(obj.obj_id, self._node.keystore, owner)

        # set the output data object ids in the status
        context.pop_pending_output(obj_name, obj)
