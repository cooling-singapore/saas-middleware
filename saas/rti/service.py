from __future__ import annotations

import json
import os
import subprocess
from _stat import S_IWRITE
from stat import S_IREAD
from threading import Lock
from typing import Optional, Dict, List

from fastapi import Request
from fastapi.responses import FileResponse, Response

from saas.core.exceptions import SaaSRuntimeException
from saas.core.helpers import generate_random_string, write_json_to_file, get_timestamp_now
from saas.core.identity import Identity
from saas.core.logging import Logging
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.p2p.exceptions import PeerUnavailableError
import saas.rti.adapters.native as native_rti
import saas.rti.adapters.docker as docker_rti
from saas.rest.auth import VerifyAuthorisation, VerifyProcessorDeployed, VerifyUserIsNodeOwner, \
    VerifyUserIsJobOwnerOrNodeOwner
from saas.rti.adapters.base import RTIProcessorAdapter
from saas.rti.exceptions import JobStatusNotFoundError, GPPDataObjectNotFound, RTIException
from saas.rti.context import JobContext
from saas.rti.proxy import RTI_ENDPOINT_PREFIX
from saas.rti.schemas import ProcessorStatus, Processor, Job, Task, JobStatus, ReconnectInfo, DeployParameters, \
    Permission
from saas.dor.schemas import GitProcessorPointer
from saas.core.schemas import GithubCredentials, SSHCredentials
from saas.rest.schemas import EndpointDefinition

logger = Logging.get('rti.service')


class RTIService:
    infix_path = 'rti'

    def __init__(self, node, retain_job_history: bool = False, strict_deployment: bool = True):
        # initialise properties
        self._mutex = Lock()
        self._node = node
        self._deployed: Dict[str, RTIProcessorAdapter] = {}
        self._ssh_credentials_paths = {}
        self._jobs_path = os.path.join(self._node.datastore, 'jobs')
        self._content_keys = {}
        self._jobs_context = {}
        self._retain_job_history = retain_job_history
        self._strict_deployment = strict_deployment

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
                dor_protocol = DataObjectRepositoryP2PProtocol(self._node)
                gpp = dor_protocol.lookup_gpp(node.p2p_address, proc_id)
                if gpp:
                    return gpp

            # ignore peers that are not available
            except PeerUnavailableError:
                continue

    @property
    def retain_job_history(self) -> bool:
        return self._retain_job_history

    @property
    def strict_deployment(self) -> bool:
        return self._strict_deployment

    def job_descriptor_path(self, job_id: str) -> str:
        return os.path.join(self._jobs_path, job_id, 'job_descriptor.json')

    def job_status_path(self, job_id: str) -> str:
        return os.path.join(self._jobs_path, job_id, 'job_status.json')

    def endpoints(self) -> List[EndpointDefinition]:
        return [
            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, '',
                               self.deployed, List[Processor], None),

            EndpointDefinition('POST', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}',
                               self.deploy, Processor, [VerifyUserIsNodeOwner] if self._strict_deployment else None),

            EndpointDefinition('DELETE', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}',
                               self.undeploy, Processor, [VerifyProcessorDeployed, VerifyUserIsNodeOwner] if
                               self._strict_deployment else [VerifyProcessorDeployed]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/gpp',
                               self.gpp, GitProcessorPointer, [VerifyProcessorDeployed]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/status',
                               self.status, ProcessorStatus, [VerifyProcessorDeployed]),

            EndpointDefinition('POST', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/jobs',
                               self.submit, Job, [VerifyProcessorDeployed, VerifyAuthorisation]),

            EndpointDefinition('PUT', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/jobs',
                               self.resume, Job, [VerifyProcessorDeployed, VerifyAuthorisation]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'proc/{proc_id}/jobs',
                               self.jobs_by_proc, List[Job], [VerifyProcessorDeployed]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'job',
                               self.jobs_by_user, List[Job], [VerifyAuthorisation]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'job/{job_id}/status',
                               self.job_status, JobStatus, [VerifyUserIsJobOwnerOrNodeOwner]),

            EndpointDefinition('GET', RTI_ENDPOINT_PREFIX, 'job/{job_id}/logs',
                               self.job_logs, None, [VerifyUserIsJobOwnerOrNodeOwner]),

            EndpointDefinition('DELETE', RTI_ENDPOINT_PREFIX, 'job/{job_id}',
                               self.job_cancel, JobStatus, [VerifyUserIsJobOwnerOrNodeOwner]),

            EndpointDefinition('POST', RTI_ENDPOINT_PREFIX, 'permission/{req_id}',
                               self.put_permission, None, None)
        ]

    def deployed(self) -> List[Processor]:
        """
        Retrieves a list of all processors that are deployed by the RTI.
        """
        with self._mutex:
            return [Processor(proc_id=proc_id, gpp=adapter.gpp) for proc_id, adapter in self._deployed.items()]

    def deploy(self, proc_id: str, p: DeployParameters) -> Processor:
        """
        Deploys a processor to the RTI. By default, the processor is deployed on the same machine that hosts the RTI.
        If the processor is supposed to be deployed on a remote machine, corresponding SSH credentials have to be
        provided which the RTI can use to access the remote machine. Note that SSH credentials will be stored and used
        by the RTI to be able to access the remotely deployed processor. Deployment requires the RTI to access the
        repository that contains the processor code. If the repository is not public, corresponding GitHub credentials
        need to be provided. Note that GitHub credentials are not stored. Note that all credentials information must
        not be sent in plaintext but instead encrypted using the corresponding public encryption key of the RTI node.
        """
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
            if p.encrypted_ssh_credentials is not None:
                ssh_credentials = bytes.fromhex(p.encrypted_ssh_credentials)
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
            if p.encrypted_github_credentials is not None:
                github_credentials = bytes.fromhex(p.encrypted_github_credentials)
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
        """
        Shuts down a deployed processor and removes it from the list of deployed processor hosted by the RTI. If
        SSH credentials have been used by this processor for remote deployment, then the stored SSH credentials will
        be deleted as well.
        """
        with self._mutex:
            # remove the processor
            processor = self._deployed.pop(proc_id)

            # stop the processor and wait for it to be done
            logger.info(f"stopping processor {proc_id}...")
            processor.stop()

            # wait for processor to be stopped and to return
            logger.info(f"waiting for processor {proc_id} to be stopped...")
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
        """
        Retrieves the Git-Processor-Pointer (GPP) information of a deployed processor.
        """
        with self._mutex:
            return self._deployed[proc_id].gpp

    def status(self, proc_id: str) -> ProcessorStatus:
        """
        Retrieves status information for a deployed processor.
        """
        with self._mutex:
            return self._deployed[proc_id].status()

    def submit(self, proc_id: str, task: Task, request: Request) -> Job:
        """
        Submits a task to a deployed processor, thereby creating a new job. The job is queued and executed once the
        processor has the capacity to do so. Authorisation is required by the owner of the task/job.
        """
        with self._mutex:
            # get the user's identity and check if it's identical with that's indicated in the task
            iid = request.headers['saasauth-iid']
            if iid != task.user_iid:
                raise RTIException("Mismatching between user indicated in task and user making request", details={
                    'iid': iid,
                    'task': task
                })

            # get the processor
            proc = self._deployed.get(task.proc_id)
            if proc is None:
                raise RTIException(f"Processor {task.proc_id} not deployed", details={
                    'task': task
                })

            # create job descriptor with a generated job id
            job = Job(id=generate_random_string(8), task=task, retain=self._retain_job_history,
                      custodian=self._node.info, proc_name=proc.gpp.proc_descriptor.name,
                      t_submitted=get_timestamp_now())

            # create working directory or log a warning if it already exists
            wd_path = os.path.join(self._jobs_path, job.id)
            if os.path.isdir(wd_path):
                logger.warning(f"job working directory path '{wd_path}' already exists.")
            os.makedirs(wd_path, exist_ok=True)

            # write the job descriptor
            job_descriptor_path = self.job_descriptor_path(job.id)
            write_json_to_file(job.dict(), job_descriptor_path)

            # create job context logger
            context = JobContext(self.job_status_path(job.id), job)
            self._jobs_context[job.id] = context
            context.start()

            # add the job to the processor queue and return the job descriptor
            proc.add(context)
            return job

    def resume(self, proc_id: str, job: Job, reconnect: ReconnectInfo, request: Request) -> Job:
        """
        Attempts to resume monitoring an existing job that may have lost connectivity. This may be the case for jobs
        that are executed remotely. It is not guaranteed that resume is successful and depends on whether the
        underlying reasons for the disconnect (e.g., network outage) have been resolved. Authorisation is required by
        the owner of the job (i.e., the user that has created the job by submitting the task in the first place).
        """
        with self._mutex:
            # get the user's identity and check if it's identical with that's indicated in the task
            iid = request.headers['saasauth-iid']
            if iid != job.task.user_iid:
                raise RTIException("Mismatching between user indicated in task and user making request", details={
                    'iid': iid,
                    'task': job.task
                })

            # create a job context
            context = JobContext(self.job_status_path(job.id), job, reconnect)
            self._jobs_context[job.id] = context
            context.start()

            # add the job to the processor queue and return the job descriptor
            self._deployed[proc_id].resume(context)
            return job

    def jobs_by_proc(self, proc_id: str) -> List[Job]:
        """
        Retrieves a list of jobs processed by a processor. Any job that is pending execution or actively executed will
        be included in the list. Past jobs, i.e., jobs that have completed execution (successfully or not) will not be
        included in this list.
        """

        with self._mutex:
            # collect all jobs
            result = [*self._deployed[proc_id].pending_jobs()]
            active = [*self._deployed[proc_id].active_jobs()]
            result.extend(active)

            return result

    def jobs_by_user(self, request: Request) -> List[Job]:
        """
        Retrieves a list of jobs owned by a user. Any job that is pending execution or actively executed will be
        included in the list. Past jobs, i.e., jobs that have completed execution (successfully or not) will not be
        included in this list.
        """

        with self._mutex:
            # get the identity
            user: Identity = self._node.db.get_identity(request.headers['saasauth-iid'])

            # collect all jobs
            result = {}
            for proc in self._deployed.values():
                for pending in proc.pending_jobs():
                    result[pending.id] = pending

                for active in proc.active_jobs():
                    result[active.id] = active

            # also check the live job status loggers
            for context in self._jobs_context.values():
                result[context.job.id] = context.job

            # if the user is NOT the node owner, only return the jobs owned by the user
            if self._node.identity.id != user.id:
                filtered = []
                for job in result.values():
                    if job.task.user_iid == user.id:
                        filtered.append(job)

                return filtered

            return list(result.values())

    def job_status(self, job_id: str) -> JobStatus:
        """
        Retrieves detailed information about the status of a job. Authorisation is required by the owner of the job
        (i.e., the user that has created the job by submitting the task in the first place).
        """
        with self._mutex:
            # do we have a live job status logger?
            status_path = self.job_status_path(job_id)
            if job_id in self._jobs_context:
                context: JobContext = self._jobs_context[job_id]
                return context.status

            # does the job status file exist?
            elif os.path.isfile(status_path):
                status = JobStatus.parse_file(status_path)
                return status

            else:
                raise JobStatusNotFoundError({
                    'job_id': job_id
                })

    def job_logs(self, job_id: str) -> Response:
        """
        Attempts to retrieve the execution logs of a job. This includes stdout and stderr output that has been
        generated during job execution. Depending on the status of the job (is the job already running or has it
        finished execution?) and on the underlying implementation of the processor (is stdout/stderr output generated?)
        logs may or may not be available. Logs will be archived using tar.gz and delivered as binary stream for the
        client to download.
        """
        # collect log files (if they exist)
        existing = []
        for filename in ['execute_sh.stdout', 'execute_sh.stderr']:
            log_path = os.path.join(self._jobs_path, job_id, filename)
            if os.path.isfile(log_path):
                existing.append(os.path.basename(log_path))

        # do we have anything?
        if not existing:
            raise RTIException("No execute logs available.", details={
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
            raise SaaSRuntimeException('Archiving execute logs failed', details={
                'returncode': e.returncode,
                'command': command,
                'stdout': e.stdout.decode('utf-8'),
                'stderr': e.stderr.decode('utf-8')
            })

    def job_cancel(self, job_id: str) -> JobStatus:
        """
        Attempts to cancel a running job. Depending on the implementation of the processor, this may or may not be
        possible.
        """
        with self._mutex:
            # do we have a live job status logger?
            if job_id in self._jobs_context:
                context: JobContext = self._jobs_context[job_id]
                context.cancel()

                return context.status

            else:
                raise RTIException(f"Cannot cancel job: no job context found for {job_id} (either job was not found or "
                                   f"the job is not running any longer)")

    def put_permission(self, req_id: str, permission: Permission) -> None:
        """
        Uploads a permission for a specific request. This is normally only required in case of encrypted data objects.
        When a processor needs to process an encrypted data object, it requires the necessary permissions (and content
        key) to process the data object. For this purpose, the RTI will request the content key during the
        initialisation phase of a job. Data object Owners can then submit the required content key using this endpoint.
        The request itself is encrypted using the public key of the data object owner and provides the following
        information:
        `{
          'type': 'request_content_key',
          'req_id': 'H2dofbWhSZddTah9'
          'obj_id': '1e6e ... f6be',
          'ephemeral_public_key': 'MIIC ... Q==',
          'user_iid': 'fyll ... ev00',
          'node_id': '9mip ... x85y'
        }`
        """
        with self._mutex:
            self._content_keys[req_id] = permission.content_key

    def pop_permission(self, req_id: str) -> Optional[str]:
        with self._mutex:
            return self._content_keys.pop(req_id, None)
