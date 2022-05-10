from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from abc import abstractmethod, ABC
from enum import Enum
from threading import Lock, Thread
from typing import Optional

from saascore.api.sdk.proxies import DORProxy
from saascore.log import Logging
from saascore.cryptography.helpers import encrypt_file, decrypt_file
from saascore.cryptography.keypair import KeyPair
from saascore.cryptography.rsakeypair import RSAKeyPair
from saascore.exceptions import SaaSException, RunCommandError
from saascore.helpers import write_json_to_file, read_json_from_file, generate_random_string, validate_json, \
    get_timestamp_now
from saascore.keystore.assets.credentials import SSHCredentials

from saas.dor.exceptions import IdentityNotFoundError
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.nodedb.service import NetworkNode
from saas.p2p.exceptions import PeerUnavailableError
from saas.rti.exceptions import ProcessorNotAcceptingJobsError, UnresolvedInputDataObjectsError, \
    AccessNotPermittedError, MissingUserSignatureError, MismatchingDataTypeOrFormatError, InvalidJSONDataObjectError, \
    DataObjectContentNotFoundError, DataObjectOwnerNotFoundError

from saas.rti.status import State, StatusLogger

logger = Logging.get('rti.adapters')


class ProcessorState(Enum):
    UNINITIALISED = 'uninitialised'
    STARTING = 'starting'
    WAITING = 'waiting'
    BUSY = 'busy'
    STOPPING = 'stopping'
    STOPPED = 'stopped'


def run_command(command: str, ssh_credentials: SSHCredentials = None, timeout: int = None,
                check_exitcode: bool = True) -> subprocess.CompletedProcess:

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
    try:
        result = subprocess.run(wrapped_command, capture_output=True, check=check_exitcode, timeout=timeout)
        return result

    except subprocess.CalledProcessError as e:
        raise RunCommandError({
            'reason': 'non-zero return code',
            'returncode': e.returncode,
            'wrapped_command': wrapped_command,
            'stdout': e.stdout.decode('utf-8'),
            'stderr': e.stdout.decode('utf-8'),
            'ssh_credentials': ssh_credentials.record if ssh_credentials else None,
        })

    except subprocess.TimeoutExpired:
        raise RunCommandError({
            'reason': 'timeout',
            'wrapped_command': wrapped_command,
            'ssh_credentials': ssh_credentials.record if ssh_credentials else None,
        })


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
            'ssh_credentials': ssh_credentials.record,
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
            'ssh_credentials': ssh_credentials.record,
            'result': result
        })


def get_home_directory(ssh_credentials: SSHCredentials) -> str:
    result = run_command("realpath ~", ssh_credentials=ssh_credentials)
    _home = result.stdout.decode('utf-8').strip()

    if _home.startswith("/cygdrive/"):  # fix path for Windows machine with cygwin
        _home = _home.replace("/cygdrive/", "")
        _home = f"{_home[:1]}:{_home[1:]}"

    return _home


def is_cygwin(ssh_credentials: SSHCredentials) -> bool:
    result = run_command("uname", ssh_credentials=ssh_credentials)
    env = result.stdout.decode('utf-8').strip()
    return "cygwin" in env.lower()


def run_command_async(command: str, local_output_path: str, name: str, ssh_credentials: SSHCredentials = None) -> (str, dict):
    # determine remote output path (in case it's needed)
    # FIXME: Might not need this since ssh should open in HOME directory anyway
    _home = get_home_directory(ssh_credentials)
    remote_output_path = local_output_path.replace(os.environ['HOME'], _home)

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
            f"#!/bin/bash",
            f"{command} > {paths['stdout']} 2> {paths['stderr']} &",
            f"pid=$!",
            f"echo $pid > {paths['pid']}",
            f"wait $pid",
            f"echo $? > {paths['exitcode']}",
            f""
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
    time.sleep(0.5)
    result = run_command(f"cat {paths['pid']}", ssh_credentials=ssh_credentials, timeout=10)
    pid = result.stdout.decode('utf-8').splitlines()[0]
    logger.info(f"started async process {pid} running {'REMOTE:' if ssh_credentials else 'LOCAL:'}{paths['script']}")

    return pid, paths


def monitor_command(pid: str, paths: dict, triggers: dict = None, ssh_credentials: SSHCredentials = None,
                    pace: int = 500, max_attempts: int = 60, retry_delay: int = 10) -> None:

    logger.info(f"begin monitoring {pid} on {'REMOTE' if ssh_credentials else 'LOCAL'} machine.")
    c_stdout_lines = 0
    c_stderr_lines = 0
    t_prev = get_timestamp_now()
    n_attempts = 0

    def get_line_count(file_path: str) -> int:
        wc_result = run_command(f"wc -l {file_path}", ssh_credentials=ssh_credentials, timeout=10)
        n_lines = wc_result.stdout.decode('utf-8').splitlines()[0].split()[0]
        return int(n_lines)

    while True:
        try:
            # get the number of lines in stdout and stderr
            n_stdout_lines = get_line_count(paths['stdout'])
            n_stderr_lines = get_line_count(paths['stderr'])

            # new line count
            d_stdout_lines = n_stdout_lines - c_stdout_lines
            d_stderr_lines = n_stderr_lines - c_stderr_lines

            # no new lines at all? check if the process is still running
            if d_stdout_lines == 0 and d_stderr_lines == 0:
                # do we have an exit code file? (it is only generated when the process has terminated)
                if check_if_path_exists(paths['exitcode'], ssh_credentials=ssh_credentials, timeout=10):
                    logger.info(f"end monitoring {pid} on {'REMOTE' if ssh_credentials else 'LOCAL'} machine.")
                    break

            # do we have new STDOUT lines to process?
            if d_stdout_lines > 0:
                result = run_command(f"tail -n +{c_stdout_lines + 1} {paths['stdout']} | head -n {d_stdout_lines}",
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
            paths['remote_stdout']: paths['local_stdout'],
            paths['remote_stderr']: paths['local_stderr'],
            paths['remote_exitcode']: paths['local_exitcode']
        }

        for s, d in todo.items():
            # wait for the source to be available
            while not check_if_path_exists(s, ssh_credentials=ssh_credentials):
                logger.warning(f"resource not available at {'REMOTE:' if ssh_credentials else 'LOCAL:'}{s} -> retry in 5 seconds.")
                time.sleep(5)

            logger.info(f"copying from to local: {s} -> {d}")
            scp_remote_to_local(s, d, ssh_credentials)

    # get the error code returned by the process and raise exception if the process did not finish successfully.
    with open(paths['local_exitcode'], 'r') as f:
        line = f.readline()
        exitcode = int(line)
        if exitcode != 0:
            raise RunCommandError({
                'pid': pid,
                'exitcode': exitcode,
                'paths': paths
            })


def check_if_path_exists(path: str, ssh_credentials: SSHCredentials = None, timeout: int = None) -> bool:
    result = run_command(f"ls {path}", ssh_credentials=ssh_credentials, timeout=timeout, check_exitcode=False)
    return result.returncode == 0


def create_symbolic_link(link_path: str, target_path: str, working_directory: str = None) -> None:
    if working_directory:
        link_path = os.path.join(working_directory, link_path)
        target_path = os.path.join(working_directory, target_path)
    run_command(f"ln -sf {target_path} {link_path}")


class RTIProcessorAdapter(Thread, ABC):
    def __init__(self, proc_id: str, gpp: dict, job_wd_path: str, node) -> None:
        Thread.__init__(self, daemon=True)

        self._mutex = Lock()
        self._proc_id = proc_id
        self._gpp = gpp
        self._job_wd_path = job_wd_path
        self._node = node

        self._input_interface = {item['name']: item for item in gpp['proc_descriptor']['input']}
        self._output_interface = {item['name']: item for item in gpp['proc_descriptor']['output']}
        self._pending = []
        self._active = None
        self._state = ProcessorState.UNINITIALISED

    @property
    def id(self) -> str:
        return self._proc_id

    @property
    def gpp(self) -> dict:
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
    def execute(self, job_id: str, job_descriptor: dict, working_directory: str, status: StatusLogger) -> None:
        pass

    def stop(self) -> None:
        logger.info(f"[adapter:{self._proc_id}] received stop signal.")
        self._state = ProcessorState.STOPPING

    @abstractmethod
    def delete(self) -> None:
        pass

    def status(self) -> dict:
        with self._mutex:
            result = {
                'state': self._state.value,
                'pending': [{'job_id': item[0]['id'], 'task': item[0]['task']} for item in self._pending]
            }
            if self._active is not None:
                result['active'] = {
                    'job_id': self._active['id'],
                    'task': self._active['task']
                }

            return result

    def pre_execute(self, job_id: str, task_descriptor: dict, working_directory: str, status: StatusLogger) -> None:
        logger.info(f"[adapter:{self._proc_id}][{job_id}] perform pre-execute routine...")

        # store by-value input data objects (if any)
        self._store_value_input_data_objects(task_descriptor, working_directory, status)

        # lookup by-reference input data objects (if any)
        obj_records = self._lookup_reference_input_data_objects(task_descriptor, status)

        # fetch by-reference input data objects (if any)
        ephemeral_key = RSAKeyPair.create_new()
        pending_content_keys = self._fetch_reference_input_data_objects(ephemeral_key, task_descriptor, obj_records,
                                                                        working_directory, status)

        # decrypt by-reference input data objects (if any)
        self._decrypt_reference_input_data_objects(ephemeral_key, pending_content_keys, status)

        # verify that data types of input data objects match
        self._verify_inputs(task_descriptor, working_directory, status)

        # verify the output owner identities
        self._verify_outputs(task_descriptor, status)

    def post_execute(self, job_id: str) -> None:
        logger.info(f"[adapter:{self._proc_id}][{job_id}] perform post-execute routine...")

    def add(self, job_descriptor: dict, status: StatusLogger) -> None:
        with self._mutex:
            # are we accepting jobs?
            if self._state == ProcessorState.STOPPING or self._state == ProcessorState.STOPPED:
                raise ProcessorNotAcceptingJobsError({
                    'proc_id': self._proc_id,
                    'job_descriptor': job_descriptor
                })

            self._pending.append((job_descriptor, status))

    def pending_jobs(self) -> list[dict]:
        with self._mutex:
            return [job_descriptor for job_descriptor, _ in self._pending]

    def run(self) -> None:
        logger.info(f"[adapter:{self._proc_id}] starting up...")
        self._state = ProcessorState.STARTING
        self.startup()

        logger.info(f"[adapter:{self._proc_id}] started.")
        while self._state != ProcessorState.STOPPING and self._state != ProcessorState.STOPPED:
            # wait for a pending job (or for adapter to become inactive)
            self._active = None
            self._state = ProcessorState.WAITING
            pending_job = self._wait_for_pending_job()
            if not pending_job:
                break

            # process a job
            job_descriptor, status = pending_job
            self._active = job_descriptor
            self._state = ProcessorState.BUSY

            # set job state
            status.update_state(State.RUNNING)

            job_id = str(job_descriptor['id'])
            task_descriptor = job_descriptor['task']
            wd_path = os.path.join(self._job_wd_path, job_id)

            try:
                # perform pre-execute routine
                self.pre_execute(job_id, task_descriptor, wd_path, status)

                # instruct processor adapter to execute the job
                self.execute(job_id, task_descriptor, wd_path, status)

                # perform post-execute routine
                self.post_execute(job_id)

            except SaaSException as e:
                status.update('error', f"error while running job:\n"
                                       f"id: {e.id}\n"
                                       f"reason: {e.reason}\n"
                                       f"details: {e.details}")
                status.update_state(State.FAILED)

            except Exception as e:
                status.update('error', f"unexpected exception while running job:\n"
                                       f"exception: {e}")
                status.update_state(State.FAILED)

            else:
                status.update_state(State.SUCCESSFUL)

            # if the job history is not to be retained, delete its contents (with exception of the status and
            # the job descriptor)
            if not job_descriptor['retain']:
                exclusions = ['job_descriptor.json', 'job_status.json', '.sh.stderr', '.sh.stdout']
                logger.info(f"[adapter:{self._proc_id}][{job_id}] delete working directory contents at {wd_path} "
                            f"(exclusions: {exclusions})...")

                # collect all files in the directory
                files = os.listdir(wd_path)
                for file in files:
                    # if the item is not in the exclusion list, delete it
                    if not file.endswith(tuple(exclusions)):
                        path = os.path.join(wd_path, file)
                        if os.path.isfile(path):
                            os.remove(path)
                        elif os.path.isdir(path):
                            shutil.rmtree(path)
                        elif os.path.islink(path):
                            os.unlink(path)
                        else:
                            logger.warning(f"Encountered neither file nor directory: {path}")

        logger.info(f"[adapter:{self._proc_id}] shutting down...")
        self._state = ProcessorState.STOPPING
        self._purge_pending_jobs()
        self.shutdown()

        logger.info(f"[adapter:{self._proc_id}] shut down.")
        self._state = ProcessorState.STOPPED

    def _wait_for_pending_job(self) -> Optional[tuple[dict, StatusLogger]]:
        while True:
            with self._mutex:
                # if the adapter has become inactive, return immediately.
                if self._state == ProcessorState.STOPPING or self._state == ProcessorState.STOPPED:
                    return None

                # if there is a job, return it
                elif len(self._pending) > 0:
                    job_descriptor, status = self._pending.pop(0)
                    return job_descriptor, status

            time.sleep(0.1)

    def _purge_pending_jobs(self) -> None:
        with self._mutex:
            while len(self._pending) > 0:
                job_descriptor, status = self._pending.pop(0)
                logger.info(f"purged pending job: {job_descriptor}")

    def _lookup_reference_input_data_objects(self, task_descriptor: dict, status: StatusLogger) -> dict:
        status.update('step', f"lookup by-reference input data objects")

        # do we have any by-reference input data objects in the first place?
        pending = {item['obj_id']: item['user_signature'] if 'user_signature' in item else None
                   for item in task_descriptor['input'] if item['type'] == 'reference'}
        if len(pending) == 0:
            return {}

        # get the user identity
        user = self._node.db.get_identity(task_descriptor['user_iid'])
        if user is None:
            raise IdentityNotFoundError(task_descriptor['user_iid'])

        # lookup all referenced data objects using the P2P protocol
        protocol = DataObjectRepositoryP2PProtocol(self._node)
        found = {}
        for peer in self._node.db.get_network_all():
            # only check with peers that have a DOR
            if peer.dor_service:
                try:
                    # does the remote DOR have the data object?
                    records = protocol.lookup(peer.get_p2p_address(), [*pending.keys()], user)
                    for obj_id, record in records.items():
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
                if not item['user_has_permission']:
                    raise AccessNotPermittedError({
                        'obj_id': obj_id,
                        'user_iid': user.id
                    })

                if 'user_signature' not in item:
                    raise MissingUserSignatureError({
                        'obj_id': obj_id,
                        'user_iid': user.id
                    })

        status.remove('step')
        return found

    def _fetch_reference_input_data_objects(self, ephemeral_key: KeyPair, task_descriptor: dict, obj_records: dict,
                                            working_directory: str, status: StatusLogger) -> list[dict]:

        status.update('step', f"fetch by-reference input data objects")

        # do we have any data objects to fetch to begin with?
        if len(obj_records) == 0:
            status.remove('step')
            return []

        # get the user identity
        user = self._node.db.get_identity(task_descriptor['user_iid'])
        if user is None:
            raise IdentityNotFoundError(task_descriptor['user_iid'])

        # fetch input data objects one by one using the P2P protocol
        protocol = DataObjectRepositoryP2PProtocol(self._node)
        pending_content_keys = []
        c_hashes = {}
        for obj_id, record in obj_records.items():
            meta_path = os.path.join(working_directory, f"{obj_id}.meta")
            content_path = os.path.join(working_directory, f"{obj_id}.content")

            # fetch the data object
            custodian: NetworkNode = record['custodian']
            protocol.fetch(custodian.get_p2p_address(), obj_id, meta_path, content_path,
                           task_descriptor['user_iid'] if record['access_restricted'] else None,
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
                requests = status.get('requests', default=[])
                requests.append({
                    'req_id': req_id,
                    'receiver': user.id,
                    'request': request
                })
                status.update('requests', requests)

                # add on to the list of pending items
                pending_content_keys.append({
                    'req_id': req_id,
                    'obj_id': obj_id,
                    'path': content_path
                })

        # create symbolic links to the contents for every input AND update references with c_hash
        for item in task_descriptor['input']:
            if item['type'] == 'reference':
                create_symbolic_link(item['name'], f"{item['obj_id']}.content",
                                     working_directory=working_directory)

                create_symbolic_link(f"{item['name']}.meta", f"{item['obj_id']}.meta",
                                     working_directory=working_directory)

                item['c_hash'] = c_hashes[item['obj_id']]

        status.remove('step')
        return pending_content_keys

    def _decrypt_reference_input_data_objects(self, ephemeral_key: KeyPair, pending_content_keys: list[dict],
                                              status: StatusLogger) -> None:
        status.update('step', f"decrypt by-reference input data objects")
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
        status.remove('step')

    def _store_value_input_data_objects(self, task_descriptor: dict, working_directory: str,
                                        status: StatusLogger) -> None:
        status.update('step', f"store by-value input data objects")
        for item in task_descriptor['input']:
            # if it is a 'value' input then store it to the working directory
            if item['type'] == 'value':
                input_content_path = os.path.join(working_directory, item['name'])
                write_json_to_file(item['value'], input_content_path)
                write_json_to_file({
                    # data type can be anything (it's application specific). assuming 'JSONObject' as data type is
                    # not a good idea. instead, use the data type indicated in the input interface of the processor.
                    # however, what about the format? only json data is allowed to be used for 'by-value' input
                    # data objects. so hard-coding 'json' has data format seems justified. if the processor expects
                    # a different format, then this will raise a MismatchingDataTypeOrFormatError exception.
                    'data_type': self._input_interface[item['name']]['data_type'],
                    'data_format': 'json'
                }, f"{input_content_path}.meta")
        status.remove('step')

    def _verify_inputs(self, task_descriptor: dict, working_directory: str, status: StatusLogger) -> None:
        status.update('step', 'verify inputs: data object types and formats')
        for item in task_descriptor['input']:
            obj_name = item['name']

            # check if data type/format indicated in processor descriptor and data object descriptor match
            d0 = read_json_from_file(os.path.join(working_directory, f"{obj_name}.meta"))
            d1 = self._input_interface[obj_name]
            if d0['data_type'] != d1['data_type'] or d0['data_format'] != d1['data_format']:
                raise MismatchingDataTypeOrFormatError({
                    'obj_name': obj_name,
                    'expected': {
                        'data_type': d1['data_type'],
                        'data_format': d1['data_format']
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
        status.remove('step')

    def _verify_outputs(self, task_descriptor: dict, status: StatusLogger) -> None:
        status.update('step', 'verify outputs: data object owner identities')
        for item in task_descriptor['output']:
            owner = self._node.db.get_identity(item['owner_iid'])
            if owner is None:
                raise DataObjectOwnerNotFoundError({
                    'output_name': item['name'],
                    'owner_iid': item['owner_iid']
                })
        status.remove('step')

    def _push_data_object(self, job_id: str, obj_name: str, task_descriptor: dict, working_directory: str,
                          status: StatusLogger) -> None:

        # convenience variables
        task_out_items = {item['name']: item for item in task_descriptor['output']}
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
        owner = self._node.db.get_identity(iid=task_out['owner_iid'])
        if owner is None:
            raise DataObjectOwnerNotFoundError({
                'output_name': obj_name,
                'owner_iid': task_out['owner_iid']
            })

        # is the output a JSONObject?
        if proc_out['data_type'] == 'JSONObject' and 'schema' in proc_out:
            content = read_json_from_file(output_content_path)
            if not validate_json(content, proc_out['schema']):
                raise InvalidJSONDataObjectError({
                    'obj_name': obj_name,
                    'content': content,
                    'schema': proc_out['schema']
                })

        restricted_access = task_out['restricted_access']
        content_encrypted = task_out['content_encrypted']

        # TODO: figure out what is supposed to happen with the content key here
        content_key = encrypt_file(output_content_path, encrypt_for=owner,
                                   delete_source=True) if content_encrypted else None

        # do we have a target node specified for storing the data object?
        target_address = self._node.rest.address()
        if 'target_node_iid' in task_out:
            # check with the node db to see if we know about this node
            node_record = self._node.db.get_network(task_out['target_node_iid'])

            # extract the rest address from that node record
            target_address = node_record.get_rest_address()

        # determine recipe
        recipe = {
            'processor': {
                'proc_id': self._proc_id,
                'gpp': self._gpp
            },
            'input': [],
            'product': {
                'name': obj_name,
                'c_hash': '',
                'data_type': proc_out['data_type'],
                'data_format': proc_out['data_format']
            }
        }

        # update recipe inputs
        for item0 in task_descriptor['input']:
            spec = self._input_interface[item0['name']]
            item1 = {
                'name': item0['name'],
                'data_type': spec['data_type'],
                'data_format': spec['data_format'],
                'type': item0['type']
            }

            if item0['type'] == 'value':
                item1['value'] = item0['value']
            else:
                item1['c_hash'] = item0['c_hash']

            recipe['input'].append(item1)

        # upload the data object to the DOR (the owner is the node for now
        # so we can update tags in the next step)
        proxy = DORProxy(target_address)
        meta = proxy.add_data_object(output_content_path, self._node.identity, restricted_access, content_encrypted,
                                     proc_out['data_type'], proc_out['data_format'], self._node.identity.id, recipe)
        obj_id = meta['obj_id']

        # update tags with information from the job
        proxy.update_tags(obj_id, self._node.keystore, {
            'name': f"{obj_name}",
            'job_id': job_id
        })

        # transfer ownership to the new owner
        proxy.transfer_ownership(obj_id, self._node.keystore, owner)

        # set the output data object ids in the status
        output = status.get('output', default=[])
        output.append({
            'name': obj_name,
            'obj_id': obj_id
        })
        status.update('output', output)

