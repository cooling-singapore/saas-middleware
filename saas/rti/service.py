from __future__ import annotations

import json
import os
import subprocess
import time
import traceback
from _stat import S_IWRITE
from json import JSONDecodeError
from stat import S_IREAD
from threading import Lock
from typing import Optional, Dict, List

from fastapi import Request
from fastapi.responses import FileResponse, Response
from saascore.exceptions import RunCommandError
from saascore.keystore.identity import Identity

from saascore.log import Logging
from saascore.helpers import write_json_to_file, generate_random_string
from saascore.keystore.assets.credentials import SSHCredentials, GithubCredentials

from saas.p2p.exceptions import PeerUnavailableError
import saas.rti.adapters.native as native_rti
from saas.rest.auth import VerifyAuthorisation, VerifyUserIsJobOwner, VerifyProcessorDeployed
from saas.rest.schemas import EndpointDefinition
from saas.rti.adapters.base import RTIProcessorAdapter
from saas.rti.exceptions import JobStatusNotFoundError, JobDescriptorNotFoundError, GPPDataObjectNotFound, RTIException
from saas.rti.schemas import Permission, DeployParameters, Job, Processor
from saas.rti.status import StatusLogger, State
from saas.schemas import ProcessorStatus, JobDescriptor, GitProcessorPointer

logger = Logging.get('rti.service')


class RTIService:
    infix_path = 'rti'

    def proc_content_path(self, c_hash: str) -> str:
        return os.path.join(self._node.datastore, RTIService.infix_path, f"{c_hash}.content")

    def proc_meta_path(self, obj_id: str) -> str:
        return os.path.join(self._node.datastore, RTIService.infix_path, f"{obj_id}.meta")

    def __init__(self, node, endpoint_prefix: str, retain_job_history: bool = False):
        # initialise properties
        self._mutex = Lock()
        self._node = node
        self._endpoint_prefix = endpoint_prefix
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
            EndpointDefinition('GET', self._endpoint_prefix, '',
                               self.deployed, List[Processor], None),

            EndpointDefinition('POST', self._endpoint_prefix, 'proc/{proc_id}',
                               self.deploy, Processor, None),

            EndpointDefinition('DELETE', self._endpoint_prefix, 'proc/{proc_id}',
                               self.undeploy, Processor, [VerifyProcessorDeployed]),

            EndpointDefinition('GET', self._endpoint_prefix, 'proc/{proc_id}/gpp',
                               self.gpp, GitProcessorPointer, [VerifyProcessorDeployed]),

            EndpointDefinition('GET', self._endpoint_prefix, 'proc/{proc_id}/status',
                               self.status, ProcessorStatus, [VerifyProcessorDeployed]),

            EndpointDefinition('POST', self._endpoint_prefix, 'proc/{proc_id}/jobs',
                               self.submit, JobDescriptor, [VerifyProcessorDeployed, VerifyAuthorisation]),

            EndpointDefinition('GET', self._endpoint_prefix, 'proc/{proc_id}/jobs',
                               self.jobs, List[JobDescriptor], [VerifyProcessorDeployed]),

            EndpointDefinition('GET', self._endpoint_prefix, 'job/{job_id}/info',
                               self.job_info, Job, [VerifyUserIsJobOwner]),

            EndpointDefinition('POST', self._endpoint_prefix, 'permission/{req_id}',
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
                    ssh_credentials = SSHCredentials(ssh_credentials.host, ssh_credentials.login, key_path, False)

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
                processor = None
                # self._deployed[proc_id] = \
                #     docker_rti.RTIDockerProcessorAdapter(proc_id, gpp, content_path, self._jobs_path,
                #                                          self._node)
                #
                # # start the processor
                # processor = self._deployed[proc_id]
                # processor.start()
                #
                # # return the descriptor
                # return meta['gpp']['proc_descriptor']

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

    def submit(self, proc_id: str, task_descriptor: dict, request: Request) -> JobDescriptor:
        with self._mutex:
            # get the user's identity
            iid = request.headers['saasauth-iid']
            owner: Identity = self._node.db.get_identity(iid)

            # create job descriptor with a generated job id
            job_descriptor = JobDescriptor(id=generate_random_string(8), proc_id=proc_id, owner_iid=owner.id,
                                           task=task_descriptor, retain=self._retain_job_history)

            # create working directory or log a warning if it already exists
            wd_path = os.path.join(self._jobs_path, str(job_descriptor.id))
            if os.path.isdir(wd_path):
                logger.warning(f"job working directory path '{wd_path}' already exists.")
            os.makedirs(wd_path, exist_ok=True)

            # write the job descriptor
            job_descriptor_path = os.path.join(wd_path, 'job_descriptor.json')
            write_json_to_file(job_descriptor.dict(), job_descriptor_path)

            # create status logger
            status_path = os.path.join(wd_path, 'job_status.json')
            status = StatusLogger(status_path)
            status.update_state(State.INITIALISED)

            # add the job to the processor queue and return the job descriptor
            self._deployed[proc_id].add(job_descriptor, status)
            return job_descriptor

    def jobs(self, proc_id: str) -> List[JobDescriptor]:
        with self._mutex:
            return self._deployed[proc_id].pending_jobs()

    def job_info(self, job_id: str) -> Job:
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

            with open(descriptor_path, 'r') as f:
                descriptor = json.load(f)

            with open(status_path, 'r') as f:
                status = json.load(f)

            return Job(descriptor=descriptor, status=status)

    def put_permission(self, req_id: str, permission: Permission) -> None:
        with self._mutex:
            self._content_keys[req_id] = permission.content_key

    def pop_permission(self, req_id: str) -> Optional[str]:
        with self._mutex:
            return self._content_keys.pop(req_id, None)
