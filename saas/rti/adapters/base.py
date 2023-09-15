from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import traceback
from abc import abstractmethod, ABC
from enum import Enum
from threading import Lock, Thread
from typing import Optional, List, Tuple, Dict

from saas.core.exceptions import SaaSRuntimeException, ExceptionContent
from saas.core.helpers import decrypt_file, encrypt_file, hash_json_object
from saas.core.keypair import KeyPair
from saas.core.rsakeypair import RSAKeyPair
from saas.dor.proxy import DORProxy
from saas.core.helpers import get_timestamp_now, read_json_from_file, write_json_to_file, validate_json, \
    generate_random_string
from saas.core.logging import Logging
from saas.nodedb.exceptions import IdentityNotFoundError
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.nodedb.proxy import NodeDBProxy
from saas.p2p.exceptions import PeerUnavailableError
from saas.rti.exceptions import ProcessorNotAcceptingJobsError, UnresolvedInputDataObjectsError, \
    AccessNotPermittedError, MissingUserSignatureError, MismatchingDataTypeOrFormatError, InvalidJSONDataObjectError, \
    DataObjectContentNotFoundError, DataObjectOwnerNotFoundError, RTIException, RunCommandError
from saas.rti.context import JobContext

from saas.rti.schemas import JobStatus, ProcessorStatus, Job
from saas.dor.schemas import GitProcessorPointer, DataObject
from saas.nodedb.schemas import NodeInfo
from saas.core.schemas import SSHCredentials

logger = Logging.get('rti.adapters')


class ProcessorState(Enum):
    UNINITIALISED = 'uninitialised'
    FAILED = 'failed'
    STARTING = 'starting'
    OPERATIONAL = 'operational'
    STOPPING = 'stopping'
    STOPPED = 'stopped'


def run_command(command: str, ssh_credentials: SSHCredentials = None, timeout: int = None,
                check_exitcode: bool = True, attempts: int = 10) -> subprocess.CompletedProcess:

    # wrap the command depending on whether it is to be executed locally or remote (if ssh credentials provided)
    if ssh_credentials:
        a = ['sshpass', '-p', f"{ssh_credentials.key}"] if ssh_credentials.key_is_password else []
        b = ['-i', ssh_credentials.key] if not ssh_credentials.key_is_password else []
        c = ['-oHostKeyAlgorithms=+ssh-rsa']

        wrapped_command = [*a, 'ssh', *b, *c, '-o',
                           f"ConnectTimeout={timeout}" if timeout else '',
                           f"{ssh_credentials.login}@{ssh_credentials.host}", command]

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
                'ssh_credentials': ssh_credentials.dict() if ssh_credentials else None,
            }
            logger.error(f"[attempt:{(attempt+1)}/{attempts}] error: {error}")

        except subprocess.TimeoutExpired:
            error = {
                'reason': 'timeout',
                'wrapped_command': wrapped_command,
                'ssh_credentials': ssh_credentials.dict() if ssh_credentials else None,
            }
            logger.error(f"[attempt:{(attempt+1)}/{attempts}] error: {error}")

        time.sleep(5)

    raise RunCommandError(error)

def scp_local_to_remote(local_path: str, remote_path: str, ssh_credentials: SSHCredentials) -> None:
    # generate the wrapped command
    a = ['sshpass', '-p', ssh_credentials.key] if ssh_credentials.key_is_password else []
    b = ['-i', ssh_credentials.key] if not ssh_credentials.key_is_password else []
    c = ['-oHostKeyAlgorithms=+ssh-rsa']
    wrapped_command = [*a, 'scp', *b, *c, local_path, f"{ssh_credentials.login}@{ssh_credentials.host}:{remote_path}"]

    # execute command
    result = subprocess.run(wrapped_command, capture_output=True)
    if result.returncode != 0:
        raise RunCommandError({
            'wrapped_command': wrapped_command,
            'ssh_credentials': ssh_credentials.dict(),
            'result': result
        })


def scp_remote_to_local(remote_path: str, local_path: str, ssh_credentials: SSHCredentials) -> None:
    # generate the wrapped command
    a = ['sshpass', '-p', ssh_credentials.key] if ssh_credentials.key_is_password else []
    b = ['-i', ssh_credentials.key] if not ssh_credentials.key_is_password else []
    c = ['-oHostKeyAlgorithms=+ssh-rsa']
    wrapped_command = [*a, 'scp', *b, *c, f"{ssh_credentials.login}@{ssh_credentials.host}:{remote_path}", local_path]

    # execute command
    result = subprocess.run(wrapped_command, capture_output=True)
    if result.returncode != 0:
        raise RunCommandError({
            'wrapped_command': wrapped_command,
            'ssh_credentials': ssh_credentials.dict(),
            'result': result
        })


def get_home_directory(ssh_credentials: SSHCredentials) -> str:
    # try to determine remote the home directory using Python3 (and Python in case Python3 doesn't work)
    result = run_command("python3 -c \"import os; print(os.path.expanduser('~'))\"", ssh_credentials=ssh_credentials,
                         check_exitcode=False)
    if result.returncode != 0:
        result2 = run_command("python -c \"import os; print(os.path.expanduser('~'))\"",
                              ssh_credentials=ssh_credentials, check_exitcode=False)
        if result2.returncode != 0:
            raise SaaSRuntimeException("Cannot determine remote home directory", details={
                'result.stdout': result.stdout.decode('utf-8'),
                'result.stderr': result.stderr.decode('utf-8'),
                'result2.stdout': result2.stdout.decode('utf-8'),
                'result2.stderr': result2.stderr.decode('utf-8')
            })
        else:
            _home = result2.stdout.decode('utf-8').strip()
    else:
        _home = result.stdout.decode('utf-8').strip()

    if _home.startswith("/cygdrive/"):  # fix path for Windows machine with cygwin
        _home = _home.replace("/cygdrive/", "")
        _home = f"{_home[:1]}:{_home[1:]}"

    return _home


def is_cygwin(ssh_credentials: SSHCredentials) -> bool:
    result = run_command("uname", ssh_credentials=ssh_credentials)
    env = result.stdout.decode('utf-8').strip()
    return "cygwin" in env.lower()


def get_pid(pid_path: str, ssh_credentials: SSHCredentials = None, max_attempts: int = 10) -> str:
    # wait for the PID file to exist
    for attempt in range(max_attempts):
        # does the PID file exist?
        if check_if_path_exists(pid_path, ssh_credentials=ssh_credentials, timeout=10):
            # read and return the PID
            result = run_command(f"cat {pid_path}", ssh_credentials=ssh_credentials, timeout=10)
            temp = result.stdout.decode('utf-8').splitlines()
            if temp is None or len(temp) == 0:
                logger.debug(f"PID file content at '{pid_path}' does not contain PID (content: {temp})... "
                             f"try again (attempt={attempt}/{max_attempts})")
                time.sleep(0.5)
                continue

            # return the PID
            return temp[0]

        else:
            logger.debug(f"PID file expected at '{pid_path}' does not (yet) exist... "
                         f"try again (attempt={attempt}/{max_attempts})")
            time.sleep(0.5)

    raise RunCommandError(reason='PID file not found', details={'pid_path': pid_path})


def run_command_async(command: str, local_output_path: str, name: str,
                      ssh_credentials: SSHCredentials = None) -> (str, dict):

    # determine remote output path (in case it's needed)
    # FIXME: Might not need this since ssh should open in HOME directory anyway
    _home = get_home_directory(ssh_credentials)
    remote_output_path = _home + local_output_path.replace(os.environ['HOME'], '')

    # check if the output path exists (locally and remotely, if applicable)
    os.makedirs(local_output_path, exist_ok=True)
    if ssh_credentials is not None:
        run_command(f"mkdir -p {remote_output_path}", ssh_credentials=ssh_credentials, timeout=10)

    # determine paths
    paths = {
        'local_stdout': os.path.join(local_output_path, f"{name}.stdout"),
        'local_stderr': os.path.join(local_output_path, f"{name}.stderr"),
        'local_pid': os.path.join(local_output_path, f"{name}.pid"),
        'local_exitcode': os.path.join(local_output_path, f"{name}.exitcode"),
        'local_script': os.path.join(local_output_path, f"{name}.sh"),
        'remote_stdout': os.path.join(remote_output_path, f"{name}.stdout"),
        'remote_stderr': os.path.join(remote_output_path, f"{name}.stderr"),
        'remote_pid': os.path.join(remote_output_path, f"{name}.pid"),
        'remote_exitcode': os.path.join(remote_output_path, f"{name}.exitcode"),
        'remote_script': os.path.join(remote_output_path, f"{name}.sh"),
    }
    paths['stdout'] = paths['remote_stdout'] if ssh_credentials else paths['local_stdout']
    paths['stderr'] = paths['remote_stderr'] if ssh_credentials else paths['local_stderr']
    paths['pid'] = paths['remote_pid'] if ssh_credentials else paths['local_pid']
    paths['script'] = paths['remote_script'] if ssh_credentials else paths['local_script']
    paths['exitcode'] = paths['remote_exitcode'] if ssh_credentials else paths['local_exitcode']

    # create the run script
    with open(paths['local_script'], 'w') as f:
        f.write('\n'.join([
            "#!/bin/bash",
            f"{command} > {paths['stdout']} 2> {paths['stderr']} &",
            "pid=$!",
            f"echo $pid > {paths['pid']}",
            "wait $pid",
            f"echo $? > {paths['exitcode']}",
            ""
        ]))

    # if needed copy the run script to the remote machine
    if ssh_credentials is not None:
        scp_local_to_remote(paths['local_script'], paths['remote_script'], ssh_credentials)

    # make script executable
    run_command(f"chmod u+x {paths['script']}", ssh_credentials=ssh_credentials, timeout=10)

    # execute the script
    if is_cygwin(ssh_credentials):
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
                    pace: int = 500, max_attempts: int = 60, retry_delay: int = 10, context: JobContext = None) -> None:

    logger.info(f"begin monitoring {pid} on {'REMOTE' if ssh_credentials else 'LOCAL'} machine.")
    c_stdout_lines = 0
    c_stderr_lines = 0
    t_prev = get_timestamp_now()
    n_attempts = 0

    def get_line_count(file_path: str) -> int:
        wc_result = run_command(f"wc -l {file_path}", ssh_credentials=ssh_credentials, timeout=10)
        n_lines = wc_result.stdout.decode('utf-8').splitlines()[0].split()[0]
        return int(n_lines)

    exitcode_found = False
    while True:
        try:
            # if we have a job context, then check if the job has the job been cancelled?
            if context and context.state == JobStatus.State.CANCELLED:
                # send SIGTERM...
                logger.debug(f"[{context.job.id}] send SIGTERM to {pid}")
                run_command(f"kill {pid}", ssh_credentials=ssh_credentials, timeout=10, check_exitcode=False)

                # check if the process still exists for at most ~30 seconds or so
                for _ in range(30):
                    result = run_command(f"ps {pid}", ssh_credentials=ssh_credentials, timeout=10, check_exitcode=False)
                    if result.returncode != 0:
                        logger.debug(f"[{context.job.id}] process {pid} terminated...")
                        return

                    # process still exists
                    time.sleep(1)

                # send SIGKILL
                print(f"[{context.job.id}] send SIGKILL to {pid}")
                run_command(f"kill -9 {pid}", ssh_credentials=ssh_credentials, timeout=10, check_exitcode=False)
                return

            # get the number of lines in stdout and stderr
            n_stdout_lines = get_line_count(pid_paths['stdout'])
            n_stderr_lines = get_line_count(pid_paths['stderr'])

            # new line count
            d_stdout_lines = n_stdout_lines - c_stdout_lines
            d_stderr_lines = n_stderr_lines - c_stderr_lines

            # no new lines at all? check if the process is still running
            if d_stdout_lines == 0 and d_stderr_lines == 0:
                # do we have an exit code file? (it is only generated when the process has terminated)
                if check_if_path_exists(pid_paths['exitcode'], ssh_credentials=ssh_credentials, timeout=10):
                    logger.info(f"end monitoring {pid} on {'REMOTE' if ssh_credentials else 'LOCAL'} machine.")

                    if not exitcode_found:
                        # set the flag, wait a second to allow stdout/stderr to flush, then give it another round
                        exitcode_found = True
                        time.sleep(1.0)
                        continue
                    else:
                        break

            # do we have new STDOUT lines to process?
            if d_stdout_lines > 0:
                result = run_command(f"tail -n +{c_stdout_lines + 1} {pid_paths['stdout']} | head -n {d_stdout_lines}",
                                     ssh_credentials=ssh_credentials, timeout=10)
                lines = result.stdout.decode('utf-8').splitlines()

                # parse the lines for this round
                for line in lines:
                    if triggers is not None:
                        for pattern, info in triggers.items():
                            if pattern in line:
                                info['func'](line, info['context'])

                c_stdout_lines += d_stdout_lines

            # do we have new STDERR lines to process?
            if d_stderr_lines > 0:
                c_stderr_lines += d_stderr_lines

            # need pacing?
            t_now = get_timestamp_now()
            delay = max(pace - (t_now - t_prev), 0)
            time.sleep(delay / 1000.0)

            # if we reach here, we can reset the attempts counter
            n_attempts = 0

        # if there is an error, then this could have been caused by a unstable connection (e.g., temporary VPN
        # disconnect). wait and retry...
        except RunCommandError as e:
            # increase attempt counter and check if limit is reached -> if so, then raise an exception
            n_attempts += 1
            if n_attempts >= max_attempts:
                raise RunCommandError({
                    'info': 'too many attempts',
                    'n_attempts': n_attempts,
                    'max_attempts': max_attempts,
                    'most_recent_exception_details': e.details
                })

            else:
                logger.warning(f"error while monitoring command (attempt {n_attempts} of {max_attempts}) "
                               f"-> try again in {retry_delay} seconds. "
                               f"reason: {e.reason} details: {e.details}")
                time.sleep(retry_delay)

    # if needed copy the stdout/stderr/exitcode files from remote to the local machine
    if ssh_credentials is not None:
        todo = {
            pid_paths['remote_stdout']: pid_paths['local_stdout'],
            pid_paths['remote_stderr']: pid_paths['local_stderr'],
            pid_paths['remote_exitcode']: pid_paths['local_exitcode']
        }

        for s, d in todo.items():
            # wait for the source to be available
            while not check_if_path_exists(s, ssh_credentials=ssh_credentials):
                logger.warning(f"resource not available at {'REMOTE:' if ssh_credentials else 'LOCAL:'}{s} "
                               f"-> retry in 5 seconds.")
                time.sleep(5)

            logger.info(f"copying from remote to local: {s} -> {d}")
            scp_remote_to_local(s, d, ssh_credentials)

    # get the error code returned by the process and raise exception if the process did not finish successfully.
    with open(pid_paths['local_exitcode'], 'r') as f:
        line = f.readline()
        exitcode = int(line)
        if exitcode != 0:
            raise RunCommandError({
                'pid': pid,
                'exitcode': exitcode,
                'pid_paths': pid_paths
            })


def check_if_path_exists(path: str, ssh_credentials: SSHCredentials = None, timeout: int = None) -> bool:
    result = run_command(f"ls {path}", ssh_credentials=ssh_credentials, timeout=timeout, check_exitcode=False)
    return result.returncode == 0


def create_symbolic_link(link_path: str, target_path: str, working_directory: str = None) -> None:
    if working_directory:
        link_path = os.path.join(working_directory, link_path)
        target_path = os.path.join(working_directory, target_path)
    run_command(f"ln -sf {target_path} {link_path}")


class JobRunner(Thread):
    def __init__(self, owner: RTIProcessorAdapter, job_type: str, context: JobContext, wd_path: str):
        super().__init__()
        self._owner = owner
        self._job_type = job_type
        self._context = context
        self._wd_path = wd_path

    @property
    def job(self) -> Job:
        return self._context.job

    @property
    def context(self) -> JobContext:
        return self._context

    def run(self):
        try:
            if self._job_type == 'new':
                # perform pre-execute routine
                self._owner.pre_execute(self._wd_path, self._context)

                # instruct processor adapter to execute the job
                self._owner.execute(self._wd_path, self._context)

            elif self._job_type == 'resume':
                pass

            else:
                raise SaaSRuntimeException(f"unexpected job type '{self._job_type}'")

            # set the job state to RUNNING
            self._context.state = JobStatus.State.RUNNING

            # connect to the job and monitor its progress
            self._owner.connect_and_monitor(self._context)

            # perform post-execute routine
            self._owner.post_execute(self._context.job.id)

            # if we reach here the job is either running or cancelled
            if self._context.state not in [JobStatus.State.RUNNING, JobStatus.State.CANCELLED]:
                raise SaaSRuntimeException(f"encountered unexpected state '{self._context.state.value}'")

            # if the job is 'running' we can set it to 'successful' because it has reached here without any issues
            if self._context.state == JobStatus.State.RUNNING:
                self._context.state = JobStatus.State.SUCCESSFUL

            # if the job history is not to be retained, delete its contents (with exception to the status and
            # the job descriptor)
            if not self._context.job.retain:
                exclusions = ['job_descriptor.json', 'job_status.json', 'execute_sh.stderr', 'execute_sh.stdout',
                              'execute_sh.pid', 'execute.sh']
                logger.info(f"[adapter:{self._owner.id}][{self._context.job.id}] delete working directory contents "
                            f"at {self._wd_path} (exclusions: {exclusions})...")

                # collect all files in the directory
                files = os.listdir(self._wd_path)
                for file in files:
                    # if the item is not in the exclusion list, delete it
                    if not file.endswith(tuple(exclusions)):
                        path = os.path.join(self._wd_path, file)
                        if os.path.isfile(path):
                            os.remove(path)
                        elif os.path.isdir(path):
                            shutil.rmtree(path)
                        elif os.path.islink(path):
                            os.unlink(path)
                        else:
                            logger.warning(f"Encountered neither file nor directory: {path}")

        except RunCommandError as e:
            # add the trace to the exception details
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            logger.debug(trace)
            details = e.details
            details['trace'] = trace

            self._context.add_error(
                'error (timeout?) while running job', ExceptionContent(id=e.id, reason=e.reason, details=details)
            )
            self._context.state = JobStatus.State.TIMEOUT

        except SaaSRuntimeException as e:
            # add the trace to the exception details
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            logger.debug(trace)
            details = e.details
            details['trace'] = trace

            self._context.add_error(
                'error (SaaS) while running job', ExceptionContent(id=e.id, reason=e.reason, details=details)
            )
            self._context.state = JobStatus.State.FAILED

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            self._context.add_error(
                'unexpected exception while running job',
                ExceptionContent(id='none', reason=f"{e}", details={'trace': trace}))
            self._context.state = JobStatus.State.FAILED

        # remove the job from the active set
        self._owner.pop_job_runner(self.job.id)

    def cancel(self):
        self._context.cancel()


class RTIProcessorAdapter(Thread, ABC):
    def __init__(self, proc_id: str, gpp: GitProcessorPointer, job_wd_path: str, node, job_concurrency: bool) -> None:
        Thread.__init__(self, daemon=True)

        self._mutex = Lock()
        self._proc_id = proc_id
        self._gpp = gpp
        self._job_wd_path = job_wd_path
        self._node = node
        self._job_concurrency = job_concurrency

        self._input_interface = {item.name: item for item in gpp.proc_descriptor.input}
        self._output_interface = {item.name: item for item in gpp.proc_descriptor.output}
        self._pending: List[Tuple[str, JobContext]] = []
        self._active: Dict[str, JobRunner] = {}
        self._state = ProcessorState.UNINITIALISED

    @property
    def id(self) -> str:
        return self._proc_id

    @property
    def gpp(self) -> GitProcessorPointer:
        return self._gpp

    @property
    def state(self) -> ProcessorState:
        return self._state

    @abstractmethod
    def startup(self) -> None:
        pass

    @abstractmethod
    def shutdown(self) -> None:
        pass

    @abstractmethod
    def execute(self, working_directory: str, context: JobContext) -> None:
        pass

    @abstractmethod
    def connect_and_monitor(self, context: JobContext) -> None:
        pass

    def stop(self) -> None:
        logger.info(f"[adapter:{self._proc_id}][{self._state}] received stop signal.")
        self._state = ProcessorState.STOPPING

    @abstractmethod
    def delete(self) -> None:
        pass

    def status(self) -> ProcessorStatus:
        with self._mutex:
            return ProcessorStatus(
                state=self._state.value,
                pending=[context.job for _, context in self._pending],
                active=[runner.job for _, runner in self._active.items()]
            )

    def pre_execute(self, working_directory: str, context: JobContext) -> None:
        logger.info(f"[adapter:{self._proc_id}][{self._state}][{context.job.id}] perform pre-execute routine...")

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
        logger.info(f"[adapter:{self._proc_id}][{self._state}][{job_id}] perform post-execute routine...")

    def add(self, context: JobContext) -> None:
        with self._mutex:
            # are we accepting jobs?
            if self._state == ProcessorState.STOPPING or self._state == ProcessorState.STOPPED:
                raise ProcessorNotAcceptingJobsError({
                    'proc_id': self._proc_id,
                    'job': context.job.dict()
                })

            self._pending.append(("new", context))

    def resume(self, context: JobContext) -> None:
        with self._mutex:
            # are we accepting jobs?
            if self._state == ProcessorState.STOPPING or self._state == ProcessorState.STOPPED:
                raise ProcessorNotAcceptingJobsError({
                    'proc_id': self._proc_id,
                    'job': context.job.dict()
                })

            self._pending.append(('resume', context))

    def job_context(self, job_id: str) -> Optional[JobContext]:
        with self._mutex:
            if job_id in self._active:
                return self._active[job_id].context

            else:
                for job_type, context in self._pending:
                    if context.job.id == job_id:
                        return context

            return None

    def pending_jobs(self) -> List[Job]:
        with self._mutex:
            return [context.job for _, context in self._pending]

    def active_jobs(self) -> List[Job]:
        with self._mutex:
            return [runner.job for _, runner in self._active.items()]

    def pop_job_runner(self, job_id: str) -> Optional[JobRunner]:
        with self._mutex:
            runner = self._active.pop(job_id) if job_id in self._active else None
            return runner

    def run(self) -> None:
        logger.info(f"[adapter:{self._proc_id}][{self._state}] has started.")

        # start-up the adapter
        try:
            self._state = ProcessorState.STARTING
            logger.info(f"[adapter:{self._proc_id}][{self._state}] performing startup routine...")
            self.startup()

        except SaaSRuntimeException as e:
            self._state = ProcessorState.FAILED
            logger.error(f"[adapter:{self._proc_id}][{self._state}] start-up failed: [{e.id}] {e.reason} {e.details}")

        except Exception as e:
            self._state = ProcessorState.FAILED
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            logger.error(f"[adapter:{self._proc_id}][{self._state}] start-up failed: {e}\n{trace}")

        else:
            self._state = ProcessorState.OPERATIONAL
            logger.info(f"[adapter:{self._proc_id}][{self._state}] has started up.")

        # while the processor is not stopped, and there are pending jobs, execute them
        # (either in sequence or concurrently)
        while self._state == ProcessorState.OPERATIONAL:
            # can we add a job? do we have a job?
            if (self._job_concurrency or len(self._active) == 0) and len(self._pending) > 0:
                # get the job
                with self._mutex:
                    job_type, context = self._pending.pop(0)

                    # create a job runner
                    wd_path = os.path.join(self._job_wd_path, context.job.id)
                    runner = JobRunner(self, job_type, context, wd_path)
                    self._active[context.job.id] = runner

                # start the job runner
                logger.info(f"[adapter:{self._proc_id}][{self._state}] starting job runner for {runner.job.id}.")
                runner.start()

            # if not, then wait a bit...
            else:
                time.sleep(0.25)

        # purge jobs before shutting down
        with self._mutex:
            for job_type, context in self._pending:
                logger.info(
                    f"[adapter:{self._proc_id}][{self._state}] purged pending job: {job_type} {context.status.job}"
                )
            self._pending = []

            for job_id, runner in self._active.items():
                runner.cancel()
                logger.info(f"[adapter:{self._proc_id}][{self._state}] purged active job: {runner.job}")
            self._active = {}

        logger.info(f"[adapter:{self._proc_id}][{self._state}] performing shutdown routine...")
        self.shutdown()

        self._state = ProcessorState.STOPPED
        logger.info(f"[adapter:{self._proc_id}][{self._state}] has stopped.")

    def _lookup_reference_input_data_objects(self, context: JobContext) -> dict:
        context.make_note('step', "lookup by-reference input data objects")

        # do we have any by-reference input data objects in the first place?
        pending = {item.obj_id: item.user_signature if item.user_signature else None
                   for item in context.job.task.input if item.type == 'reference'}
        if len(pending) == 0:
            return {}

        # get the user identity
        user = self._node.db.get_identity(context.job.task.user_iid)
        if user is None:
            raise IdentityNotFoundError(context.job.task.user_iid)

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

        context.make_note('step', "fetch by-reference input data objects")

        # do we have any data objects to fetch to begin with?
        if len(obj_records) == 0:
            context.remove_note('step')
            return []

        # get the user identity
        user = self._node.db.get_identity(context.job.task.user_iid)
        if user is None:
            raise IdentityNotFoundError(context.job.task.user_iid)

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
                           context.job.task.user_iid if record['access_restricted'] else None,
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
                context.make_note('requests', requests)

                # add on to the list of pending items
                pending_content_keys.append({
                    'req_id': req_id,
                    'obj_id': obj_id,
                    'path': content_path
                })

        # create symbolic links to the contents for every input AND update references with c_hash
        for item in context.job.task.input:
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
        context.make_note('step', "decrypt by-reference input data objects")
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
        context.make_note('step', "store by-value input data objects")
        for item in context.job.task.input:
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
        context.make_note('step', 'verify inputs: data object types and formats')
        for item in context.job.task.input:
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
        context.make_note('step', 'verify outputs: data object owner identities')
        for item in context.job.task.output:
            owner = self._node.db.get_identity(item.owner_iid)
            if owner is None:
                raise DataObjectOwnerNotFoundError({
                    'output_name': item.name,
                    'owner_iid': item.owner_iid
                })
        context.remove_note('step')

    def _push_data_object(self, obj_name: str, working_directory: str, context: JobContext) -> None:
        # convenience variables
        task_out_items = {item.name: item for item in context.job.task.output}
        task_out = task_out_items[obj_name]
        proc_out = self._output_interface[obj_name]

        # check if the output data object exists
        output_content_path = os.path.join(working_directory, obj_name)
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
        for item0 in context.job.task.input:
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
        meta = proxy.add_data_object(output_content_path, self._node.identity, restricted_access, content_encrypted,
                                     proc_out.data_type, proc_out.data_format, recipe=recipe)

        # update tags with information from the job
        meta = proxy.update_tags(meta.obj_id, self._node.keystore, [
            DataObject.Tag(key='name', value=obj_name),
            DataObject.Tag(key='job_id', value=context.job.id)
        ])

        # transfer ownership to the new owner
        meta = proxy.transfer_ownership(meta.obj_id, self._node.keystore, owner)

        # set the output data object ids in the status
        context.set_output(obj_name, meta)
