import os
import logging
import json

from threading import Lock
from typing import Optional

from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.keystore.assets.credentials import SSHCredentials
from saas.p2p.exceptions import PeerUnavailableError
from saas.rti.adapters.adapters import RTIProcessorAdapter
from saas.rti.adapters.docker import RTIDockerProcessorAdapter
from saas.rti.adapters.native import RTINativeProcessorAdapter
from saas.rti.exceptions import JobStatusNotFoundError, JobDescriptorNotFoundError, \
    ProcessorNotDeployedError, UnexpectedGPPMetaInformation, GPPDataObjectNotFound
from saas.rti.status import StatusLogger, State

from saas.helpers import write_json_to_file, generate_random_string, read_json_from_file

logger = logging.getLogger('rti.service')


class RuntimeInfrastructureService:
    infix_path = 'rti'

    def proc_content_path(self, c_hash: str) -> str:
        return os.path.join(self._node.datastore(), RuntimeInfrastructureService.infix_path, f"{c_hash}.content")

    def proc_descriptor_path(self, obj_id: str) -> str:
        return os.path.join(self._node.datastore(), RuntimeInfrastructureService.infix_path, f"{obj_id}.descriptor")

    def __init__(self, node, ssh_credentials: SSHCredentials = None) -> None:
        self._mutex = Lock()
        self._node = node
        self._deployed_processors = {}
        self._jobs_path = os.path.join(self._node.datastore(), 'jobs')
        self._content_keys = {}
        self._ssh_credentials = ssh_credentials

        # initialise directories
        os.makedirs(self._jobs_path, exist_ok=True)
        os.makedirs(os.path.join(self._node.datastore(), RuntimeInfrastructureService.infix_path), exist_ok=True)

    def deploy(self, proc_id: str, deployment: str) -> dict:
        # is the processor already deployed?
        with self._mutex:
            if proc_id in self._deployed_processors:
                logger.warning(f"processor {proc_id} already deployed -> do no redeploy and return descriptor only")
                return self._deployed_processors[proc_id].get_descriptor()

            # search the network for the GPP data object
            for network_node in self._node.db.get_network_all():
                # skip this node if doesn't have a DOR
                if network_node['dor_service'] is False:
                    continue

                # try to fetch the data object using the P2P protocol
                try:
                    protocol = DataObjectRepositoryP2PProtocol(self._node)

                    # does the remote DOR have the data object?
                    records = protocol.lookup(network_node['p2p_address'], [proc_id])
                    if proc_id not in records:
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
                    descriptor_path = self.proc_descriptor_path(proc_id)
                    content_path = self.proc_content_path(record['c_hash'])
                    protocol.fetch(network_node['p2p_address'], proc_id, descriptor_path, content_path)

                    # load the descriptor
                    descriptor = read_json_from_file(descriptor_path)

                    # create an RTI adapter instance
                    if deployment == 'native':
                        # do we have a ssh profile to use?

                        self._deployed_processors[proc_id]: RTIProcessorAdapter = \
                            RTINativeProcessorAdapter(proc_id, descriptor['proc_descriptor'], content_path,
                                                      self._jobs_path, self._node,
                                                      ssh_credentials=self._ssh_credentials)

                    elif deployment == 'docker':
                        self._deployed_processors[proc_id]: RTIProcessorAdapter = \
                            RTIDockerProcessorAdapter(proc_id, descriptor['proc_descriptor'], content_path, self._node)

                    # start the processor
                    processor = self._deployed_processors[proc_id]
                    processor.start()

                    # return the descriptor
                    return descriptor['proc_descriptor']

                # ignore peers that are not available
                except PeerUnavailableError:
                    continue

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
            processor.stop()
            processor.join()

            return processor.descriptor

    def is_deployed(self, proc_id: str) -> bool:
        with self._mutex:
            return proc_id in self._deployed_processors

    def get_deployed(self) -> list[dict]:
        with self._mutex:
            return [{
                'proc_id': proc_id,
                'proc_descriptor': adapter.descriptor
            } for proc_id, adapter in self._deployed_processors.items()]

    def get_descriptor(self, proc_id: str) -> dict:
        with self._mutex:
            # do we have this processor deployed?
            if proc_id not in self._deployed_processors:
                raise ProcessorNotDeployedError({
                    'proc_id': proc_id
                })

            return self._deployed_processors[proc_id].descriptor

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
                'task': task_descriptor
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
