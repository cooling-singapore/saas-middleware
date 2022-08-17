from __future__ import annotations

import json
import os
from _stat import S_IWRITE
from stat import S_IREAD
from threading import Lock
from typing import Optional, Dict

from saascore.log import Logging
from saascore.helpers import write_json_to_file, generate_random_string, read_json_from_file
from saascore.keystore.assets.credentials import SSHCredentials, GithubCredentials

import saas.node
import saas.dor.protocol as dor_prot
from saas.p2p.exceptions import PeerUnavailableError
import saas.rti.adapters.docker as docker_rti
import saas.rti.adapters.native as native_rti
from saas.rti.adapters.base import RTIProcessorAdapter
from saas.rti.exceptions import JobStatusNotFoundError, JobDescriptorNotFoundError, \
    ProcessorNotDeployedError, UnexpectedGPPMetaInformation, GPPDataObjectNotFound
from saas.rti.status import StatusLogger, State

logger = Logging.get('rti.service')


class RuntimeInfrastructureService:
    infix_path = 'rti'

    def proc_content_path(self, c_hash: str) -> str:
        return os.path.join(self._node.datastore, RuntimeInfrastructureService.infix_path, f"{c_hash}.content")

    def proc_meta_path(self, obj_id: str) -> str:
        return os.path.join(self._node.datastore, RuntimeInfrastructureService.infix_path, f"{obj_id}.meta")

    def __init__(self, node: saas.node.Node, retain_job_history: bool = False) -> None:
        self._mutex = Lock()
        self._node = node
        self._deployed_processors: Dict[str, RTIProcessorAdapter] = {}
        self._ssh_credentials_paths = {}
        self._jobs_path = os.path.join(self._node.datastore, 'jobs')
        self._content_keys = {}
        self._retain_job_history = retain_job_history

        # initialise directories
        os.makedirs(self._jobs_path, exist_ok=True)
        os.makedirs(os.path.join(self._node.datastore, RuntimeInfrastructureService.infix_path), exist_ok=True)

    def _store_ssh_credentials_key(self, proc_id: str, ssh_credentials: SSHCredentials) -> str:
        key_path = os.path.join(self._node.datastore, RuntimeInfrastructureService.infix_path, f"{proc_id}.ssh_key")
        self._ssh_credentials_paths[proc_id] = key_path

        # write the key to disk and change file permissions
        with open(key_path, 'w') as f:
            # Make sure that key file ends with a `\n` character or ssh would return "invalid format"
            f.write(f"{ssh_credentials.key}\n")
        os.chmod(key_path, S_IREAD | S_IWRITE)

        return key_path

    def deploy(self, proc_id: str, deployment: str, ssh_credentials: SSHCredentials = None,
               github_credentials: GithubCredentials = None, gpp_custodian: str = None) -> dict:
        with self._mutex:
            # is the processor already deployed?
            if proc_id in self._deployed_processors:
                logger.warning(f"processor {proc_id} already deployed -> do no redeploy and return descriptor only")
                return self._deployed_processors[proc_id].gpp['proc_descriptor']

            # get all nodes in the network
            network = self._node.db.get_network_all()

            # if we have a custodian, then drop all other nodes in the network
            if gpp_custodian:
                network = [item for item in network if item.iid == gpp_custodian]

            # search the network for the GPP data object
            for network_node in network:
                # skip this node if doesn't have a DOR
                if network_node.dor_service is False:
                    continue

                # try to fetch the data object using the P2P protocol
                protocol = dor_prot.DataObjectRepositoryP2PProtocol(self._node)

                # lookup the data object
                try:
                    records = protocol.lookup(network_node.get_p2p_address(), [proc_id])
                    if proc_id not in records:
                        continue

                # ignore peers that are not available
                except PeerUnavailableError:
                    continue

                # GPP data objects should not have restricted access, nor should they be encrypted. they should also
                # have data type 'Git-Processor-Pointer' and format 'json'
                record = records[proc_id]
                if record['access_restricted'] or record['content_encrypted'] or \
                        record['data_type'] != 'Git-Processor-Pointer' or record['data_format'] != 'json':
                    raise UnexpectedGPPMetaInformation({
                        'proc_id': proc_id,
                        'record': record
                    })

                # fetch the data object
                try:
                    meta_path = self.proc_meta_path(proc_id)
                    content_path = self.proc_content_path(record['c_hash'])
                    protocol.fetch(network_node.get_p2p_address(), proc_id, meta_path, content_path)

                # ignore peers that are not available
                except PeerUnavailableError:
                    continue

                # load the meta information
                meta = read_json_from_file(meta_path)

                # store the SSH credentials key (if any)
                if ssh_credentials:
                    if not ssh_credentials.key_is_password:
                        key_path = self._store_ssh_credentials_key(proc_id, ssh_credentials)
                        ssh_credentials = SSHCredentials(ssh_credentials.host, ssh_credentials.login, key_path, False)

                # create an RTI adapter instance
                if deployment == 'native':
                    self._deployed_processors[proc_id] = \
                        native_rti.RTINativeProcessorAdapter(proc_id, meta['gpp'], content_path, self._jobs_path,
                                                             self._node,
                                                             ssh_credentials=ssh_credentials,
                                                             github_credentials=github_credentials,
                                                             retain_remote_wdirs=self._retain_job_history)

                elif deployment == 'docker':
                    self._deployed_processors[proc_id] = \
                        docker_rti.RTIDockerProcessorAdapter(proc_id, meta['gpp'], content_path, self._jobs_path,
                                                             self._node)

                # start the processor
                processor = self._deployed_processors[proc_id]
                processor.start()

                # return the descriptor
                return meta['gpp']['proc_descriptor']

            # if we reach here, the GPP could not be found
            raise GPPDataObjectNotFound({
                'proc_id': proc_id
            })

    def undeploy(self, proc_id: str) -> dict:
        with self._mutex:
            # do we have this processor deployed?
            if proc_id not in self._deployed_processors:
                raise ProcessorNotDeployedError({
                    'proc_id': proc_id
                })

            # remove the processor
            processor = self._deployed_processors.pop(proc_id)

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

            return processor.gpp['proc_descriptor']

    def is_deployed(self, proc_id: str) -> bool:
        with self._mutex:
            return proc_id in self._deployed_processors

    def get_deployed(self) -> list[dict]:
        with self._mutex:
            return [{
                'proc_id': proc_id,
                'proc_descriptor': adapter.gpp['proc_descriptor']
            } for proc_id, adapter in self._deployed_processors.items()]

    def get_descriptor(self, proc_id: str) -> dict:
        with self._mutex:
            # do we have this processor deployed?
            if proc_id not in self._deployed_processors:
                raise ProcessorNotDeployedError({
                    'proc_id': proc_id
                })

            return self._deployed_processors[proc_id].gpp['proc_descriptor']

    def get_status(self, proc_id: str) -> dict:
        with self._mutex:
            # do we have this processor deployed?
            if proc_id not in self._deployed_processors:
                raise ProcessorNotDeployedError({
                    'proc_id': proc_id
                })

            return self._deployed_processors[proc_id].status()

    def submit(self, proc_id: str, task_descriptor: dict) -> dict:
        with self._mutex:
            # do we have this processor deployed?
            if proc_id not in self._deployed_processors:
                raise ProcessorNotDeployedError({
                    'proc_id': proc_id
                })

            # create job descriptor with a generated job id
            job_descriptor = {
                'id': generate_random_string(8),
                'proc_id': proc_id,
                'task': task_descriptor,
                'retain': self._retain_job_history
            }

            # create working directory or log a warning if it already exists
            wd_path = os.path.join(self._jobs_path, str(job_descriptor['id']))
            if os.path.isdir(wd_path):
                logger.warning(f"job working directory path '{wd_path}' already exists.")
            os.makedirs(wd_path, exist_ok=True)

            # write the job descriptor
            job_descriptor_path = os.path.join(wd_path, 'job_descriptor.json')
            write_json_to_file(job_descriptor, job_descriptor_path)

            # create status logger
            status_path = os.path.join(wd_path, 'job_status.json')
            status = StatusLogger(status_path)
            status.update_state(State.INITIALISED)

            # add the job to the processor queue and return the job descriptor
            self._deployed_processors[proc_id].add(job_descriptor, status)
            return job_descriptor

    def resume(self, proc_id: str, resume_descriptor: dict) -> dict:
        with self._mutex:
            paths = resume_descriptor['paths']

            # read the job descriptor
            job_descriptor_path = os.path.join(paths['local_wd'], 'job_descriptor.json')
            job_descriptor = read_json_from_file(job_descriptor_path)

            # create status logger
            status_path = os.path.join(paths['local_wd'], 'job_status.json')
            status = StatusLogger(status_path)
            status.update_state(State.INITIALISED)

            # add the job to the processor queue and return the job descriptor
            self._deployed_processors[proc_id].resume(resume_descriptor, status)
            return job_descriptor

    def get_jobs(self, proc_id: str) -> list[dict]:
        with self._mutex:
            # do we have this processor deployed?
            if proc_id not in self._deployed_processors:
                raise ProcessorNotDeployedError({
                    'proc_id': proc_id
                })

            return self._deployed_processors[proc_id].pending_jobs()

    def get_job_info(self, job_id: str) -> dict:
        with self._mutex:
            # does the descriptor exist?
            descriptor_path = os.path.join(self._jobs_path, str(job_id), 'job_descriptor.json')
            if not os.path.isfile(descriptor_path):
                raise JobDescriptorNotFoundError({
                    'job_id': job_id
                })

            # does the job status file exist?
            status_path = os.path.join(self._jobs_path, str(job_id), 'job_status.json')
            if not os.path.isfile(status_path):
                raise JobStatusNotFoundError({
                    'job_id': job_id
                })

            with open(descriptor_path, 'r') as f:
                descriptor = json.load(f)

            with open(status_path, 'r') as f:
                status = json.load(f)

            return {
                'job_descriptor': descriptor,
                'status': status
            }

    def put_permission(self, req_id: str, content_key: str) -> None:
        with self._mutex:
            self._content_keys[req_id] = content_key

    def pop_permission(self, req_id: str) -> Optional[str]:
        with self._mutex:
            return self._content_keys.pop(req_id, None)
