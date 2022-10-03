from __future__ import annotations

import json
import os
import subprocess
import time
from _stat import S_IWRITE
from json import JSONDecodeError
from stat import S_IREAD
from threading import Lock
from typing import Optional, Dict, List, Union, Literal

from fastapi import Request
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from saas.exceptions import RunCommandError
from saas.helpers import generate_random_string, write_json_to_file
from saas.log import Logging
from saas.p2p.exceptions import PeerUnavailableError
import saas.rti.adapters.native as native_rti
import saas.rti.adapters.docker as docker_rti
from saas.rest.auth import VerifyAuthorisation, VerifyUserIsJobOwner, VerifyProcessorDeployed
from saas.rti.adapters.base import RTIProcessorAdapter
from saas.rti.exceptions import JobStatusNotFoundError, JobDescriptorNotFoundError, GPPDataObjectNotFound, RTIException
from saas.rti.proxy import RTI_ENDPOINT_PREFIX
from saas.rti.status import StatusLogger, State
from saas.rti.schemas import ProcessorStatus, Processor, Job, Task, ResumableJob, JobStatus
from saas.dor.schemas import GitProcessorPointer
from saas.keystore.schemas import GithubCredentials, SSHCredentials
from saas.rest.schemas import EndpointDefinition

logger = Logging.get('rti.service')


class Permission(BaseModel):
    req_id: str
    content_key: str


def _try_load_json(path: str, max_attempts: int = 10, delay: float = 0.5) -> Union[List, Dict]:
    for i in range(max_attempts):
        try:
            with open(path, 'r') as f:
                content = json.load(f)
                return content
        except JSONDecodeError:
            logger.warning(f"could not parse JSON content in {path} (attempt: {i + 1}) "
                           f"-> trying again in {delay} seconds...")
            time.sleep(delay)


class DeployParameters(BaseModel):
    deployment: Union[Literal['native', 'docker']]
    ssh_credentials: Optional[str]
    github_credentials: Optional[str]
    gpp_custodian: Optional[str]


class RTIService:
    infix_path = 'rti'

    def proc_content_path(self, c_hash: str) -> str:
        return os.path.join(self._node.datastore, RTIService.infix_path, f"{c_hash}.content")

    def proc_meta_path(self, obj_id: str) -> str:
        return os.path.join(self._node.datastore, RTIService.infix_path, f"{obj_id}.meta")

    def __init__(self, node, retain_job_history: bool = False):
        # initialise properties
        self._mutex = Lock()
        self._node = node
        self._deployed: Dict[str, RTIProcessorAdapter] = {}
        self._ssh_credentials_paths = {}
        self._jobs_path = os.path.join(self._node.datastore, 'jobs')
        self._content_keys = {}
        self._retain_job_history = retain_job_history

        # initialise directories
        os.makedirs(self._jobs_path, exist_ok=True)
        os.makedirs(os.path.join(self._node.datastore, RTIService.infix_path), exist_ok=True)

    def _store_ssh_credentials_key(self, proc_id: str, ssh_credentials: SSHCredentials) -> str:
        key_path = os.path.join(self._node.datastore, RTIService.infix_path, f"{proc_id}.ssh_key")
        self._ssh_credentials_paths[proc_id] = key_path

        # write the key to disk and change file permissions
        with open(key_path, 'w') as f:
            # Make sure that key file ends with a `\n` character or ssh would return "invalid format"
            f.write(f"{ssh_credentials.key}\n")
        os.chmod(key_path, S_IREAD | S_IWRITE)

        return key_path

    def _find_gpp_in_network(self, proc_id: str, gpp_custodian: str = None) -> Optional[GitProcessorPointer]:
        # get all nodes in the network (and filter by custodian if any)
        network = self._node.db.get_network()
        if gpp_custodian:
            network = [item for item in network if item.iid == gpp_custodian]

        # search the network for the GPP data object
        for node in network:
            # skip this node if doesn't have a DOR
            if node.dor_service is False:
                continue

            try:
                # lookup the GPP data object
                gpp = self._node.dor.protocol.lookup_gpp(node.p2p_address, proc_id)
                if gpp:
                    return gpp

            # ignore peers that are not available
            except PeerUnavailableError:
                continue

    def job_descriptor_path(self, job_id: str) -> str:
        return os.path.join(self._jobs_path, job_id, 'job_descriptor.json')

    def job_status_path(self, job_id: str) -> str:
        return os.path.join(self._jobs_path, job_id, 'job_status.json')

    def endpoints(self) -> List[EndpointDefinition]:
        return [
            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, '',
                               self.deployed, List[Processor], None),

            EndpointDefinition('POST', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}',
                               self.deploy, Processor, None),

            EndpointDefinition('DELETE', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}',
                               self.undeploy, Processor, [VerifyProcessorDeployed]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/gpp',
                               self.gpp, GitProcessorPointer, [VerifyProcessorDeployed]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/status',
                               self.status, ProcessorStatus, [VerifyProcessorDeployed]),

            EndpointDefinition('POST', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/jobs',
                               self.submit, Job, [VerifyProcessorDeployed, VerifyAuthorisation]),

            EndpointDefinition('PUT', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/jobs',
                               self.resume, Job, [VerifyProcessorDeployed, VerifyAuthorisation]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/jobs',
                               self.jobs, List[Job], [VerifyProcessorDeployed]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'job/{job_id}/status',
                               self.job_status, JobStatus, [VerifyUserIsJobOwner]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'job/{job_id}/logs',
                               self.job_logs, None, [VerifyUserIsJobOwner]),

            EndpointDefinition('POST', RTI_ENDPOINT_PREFIX, 'permission/{req_id}',
                               self.put_permission, None, None)
        ]

    def deployed(self) -> List[Processor]:
        with self._mutex:
            return [Processor(proc_id=proc_id, gpp=adapter.gpp) for proc_id, adapter in self._deployed.items()]

    def deploy(self, proc_id: str, p: DeployParameters) -> Processor:
        with self._mutex:
            # is the processor already deployed?
            if proc_id in self._deployed:
                logger.warning(f"processor {proc_id} already deployed -> do no redeploy and return descriptor only")
                return Processor(proc_id=proc_id, gpp=self._deployed[proc_id].gpp)

            # try to find the GPP data object for this processor
            gpp = self._find_gpp_in_network(proc_id)
            if gpp is None:
                raise GPPDataObjectNotFound(details={
                    'proc_id': proc_id
                })

            # decrypt SSH credentials (if any)
            if p.ssh_credentials is not None:
                ssh_credentials = bytes.fromhex(p.ssh_credentials)
                ssh_credentials = self._node.keystore.decrypt(ssh_credentials)
                ssh_credentials = ssh_credentials.decode('utf-8')
                ssh_credentials = json.loads(ssh_credentials)
                ssh_credentials = SSHCredentials(host=ssh_credentials['host'],
                                                 login=ssh_credentials['login'],
                                                 key=ssh_credentials['key'],
                                                 key_is_password=ssh_credentials['key_is_password'])

                # if the credentials are NOT password-based, store the key to disk
                if not ssh_credentials.key_is_password:
                    key_path = self._store_ssh_credentials_key(proc_id, ssh_credentials)
                    ssh_credentials = SSHCredentials(host=ssh_credentials.host, login=ssh_credentials.login,
                                                     key=key_path, key_is_password=False)

            else:
                ssh_credentials = None

            # decrypt Github credentials (if any)
            if p.github_credentials is not None:
                github_credentials = bytes.fromhex(p.github_credentials)
                github_credentials = self._node.keystore.decrypt(github_credentials)
                github_credentials = github_credentials.decode('utf-8')
                github_credentials = json.loads(github_credentials)
                github_credentials = GithubCredentials(login=github_credentials['login'],
                                                       personal_access_token=github_credentials[
                                                           'personal_access_token'])
            else:
                github_credentials = None

            if p.deployment == 'native':
                # create a native RTI adapter instance
                processor = native_rti.RTINativeProcessorAdapter(proc_id, gpp, self._jobs_path, self._node,
                                                                 ssh_credentials=ssh_credentials,
                                                                 github_credentials=github_credentials,
                                                                 retain_remote_wdirs=self._retain_job_history)

            elif p.deployment == 'docker':
                # create a Docker RTI adapter instance
                processor = docker_rti.RTIDockerProcessorAdapter(proc_id, gpp, self._jobs_path, self._node,
                                                                 ssh_credentials=ssh_credentials,
                                                                 github_credentials=github_credentials)

        # register and start the instance as deployed
        self._deployed[proc_id] = processor
        processor.start()

        return Processor(proc_id=proc_id, gpp=processor.gpp)

    def undeploy(self, proc_id: str) -> Processor:
        with self._mutex:
            # remove the processor
            processor = self._deployed.pop(proc_id)

            # stop the processor and wait for it to be done
            logger.info(f"stopping processor {proc_id}...")
            processor.stop()
            processor.join()

            # delete the processor
            logger.info(f"deleting processor {proc_id}...")
            processor.delete()

            # delete SSH credentials key (if any)
            if proc_id in self._ssh_credentials_paths:
                cred_path = self._ssh_credentials_paths[proc_id]
                logger.info(f"deleting SSH credentials at {cred_path}")
                os.remove(cred_path)
                self._ssh_credentials_paths.pop(proc_id)

            return Processor(proc_id=proc_id, gpp=processor.gpp)

    def gpp(self, proc_id: str) -> GitProcessorPointer:
        with self._mutex:
            return self._deployed[proc_id].gpp

    def status(self, proc_id: str) -> ProcessorStatus:
        with self._mutex:
            return self._deployed[proc_id].status()

    def submit(self, proc_id: str, task: Task, request: Request) -> Job:
        with self._mutex:
            # get the user's identity and check if it's identical with that's indicated in the task
            iid = request.headers['saasauth-iid']
            if iid != task.user_iid:
                raise RTIException(f"Mismatching between user indicated in task and user making request", details={
                    'iid': iid,
                    'task': task
                })

            # create job descriptor with a generated job id
            job = Job(id=generate_random_string(8), task=task, retain=self._retain_job_history)

            # create working directory or log a warning if it already exists
            wd_path = os.path.join(self._jobs_path, job.id)
            if os.path.isdir(wd_path):
                logger.warning(f"job working directory path '{wd_path}' already exists.")
            os.makedirs(wd_path, exist_ok=True)

            # write the job descriptor
            job_descriptor_path = os.path.join(wd_path, 'job_descriptor.json')
            write_json_to_file(job.dict(), job_descriptor_path)

            # create status logger
            status_path = os.path.join(wd_path, 'job_status.json')
            status = StatusLogger(status_path)
            status.update_state(State.INITIALISED)

            # add the job to the processor queue and return the job descriptor
            self._deployed[proc_id].add(job, status)
            return job

    def resume(self, proc_id: str, job: ResumableJob, request: Request) -> Job:
        with self._mutex:
            # get the user's identity and check if it's identical with that's indicated in the task
            iid = request.headers['saasauth-iid']
            if iid != job.task.user_iid:
                raise RTIException(f"Mismatching between user indicated in task and user making request", details={
                    'iid': iid,
                    'task': job.task
                })

            # # read the job descriptor
            # job_descriptor_path = os.path.join(job.paths['local_wd'], 'job_descriptor.json')
            # job_descriptor = JobDescriptor.parse_obj(_try_load_json(job_descriptor_path))

            # create status logger
            status_path = os.path.join(job.paths['local_wd'], 'job_status.json')
            status = StatusLogger(status_path)
            status.update_state(State.INITIALISED)

            # add the job to the processor queue and return the job descriptor
            self._deployed[proc_id].resume(job, status)
            return job

    def jobs(self, proc_id: str) -> List[Job]:
        with self._mutex:
            return self._deployed[proc_id].pending_jobs()

    def job_status(self, job_id: str) -> JobStatus:
        with self._mutex:
            # does the descriptor exist?
            descriptor_path = self.job_descriptor_path(job_id)
            if not os.path.isfile(descriptor_path):
                raise JobDescriptorNotFoundError({
                    'job_id': job_id
                })

            # does the job status file exist?
            status_path = self.job_status_path(job_id)
            if not os.path.isfile(status_path):
                raise JobStatusNotFoundError({
                    'job_id': job_id
                })

            # # do we have re-connect information?
            # reconnect_info_path = os.path.join(self._jobs_path, job_id, 'job_reconnect.json')
            # if os.path.isfile(reconnect_info_path):
            #     reconnect_info = _try_load_json(reconnect_info_path)
            # else:
            #     reconnect_info = {}

            # try to load the descriptor and parse it
            job_content = _try_load_json(descriptor_path)
            job = ResumableJob.parse_obj(job_content) if 'pid' in job_content else Job.parse_obj(job_content)

            # try to load the status and extract the state
            status = _try_load_json(status_path)
            if 'state' not in status:
                raise RTIException("Invalid job status: no state information found", details={
                    'status': status
                })
            state = status['state']

            return JobStatus(state=state, status=status, job=job)

    def job_logs(self, job_id: str) -> Response:
        # collect log files (if they exist)
        existing = []
        for filename in ['execute_sh.stdout', 'execute_sh.stderr']:
            log_path = os.path.join(self._jobs_path, job_id, filename)
            if os.path.isfile(log_path):
                existing.append(os.path.basename(log_path))

        # do we have anything?
        if not existing:
            raise RTIException(f"No execute logs available.", details={
                'job_id': job_id
            })

        # build the command for archiving the logs
        wd_path = os.path.join(self._jobs_path, job_id)
        archive_path = os.path.join(self._jobs_path, job_id, 'execute_logs.tar.gz')
        command = ['tar', 'czf', archive_path, '-C', wd_path] + existing

        try:
            # archive the logs and return as stream
            subprocess.run(command, capture_output=True, check=True)
            return FileResponse(archive_path, media_type='application/octet-stream')

        except subprocess.CalledProcessError as e:
            raise RunCommandError({
                'reason': 'archiving execute logs failed',
                'returncode': e.returncode,
                'command': command,
                'stdout': e.stdout.decode('utf-8'),
                'stderr': e.stderr.decode('utf-8')
            })

    def put_permission(self, req_id: str, permission: Permission) -> None:
        with self._mutex:
            self._content_keys[req_id] = permission.content_key

    def pop_permission(self, req_id: str) -> Optional[str]:
        with self._mutex:
            return self._content_keys.pop(req_id, None)
