import os
import logging
import subprocess
import json

from threading import Lock

from saas.dor.blueprint import DORProxy
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.keystore.assets.credentials import SSHCredentials
from saas.rti.adapters.adapters import RTIProcessorAdapter
from saas.rti.adapters.docker import RTIDockerProcessorAdapter
from saas.rti.adapters.native import RTINativeProcessorAdapter
from saas.rti.status import StatusLogger, State

from saas.helpers import write_json_to_file

logger = logging.getLogger('rti.service')


class RuntimeInfrastructureService:
    infix_path = 'rti'

    def proc_content_path(self, c_hash):
        return os.path.join(self._node.datastore(), RuntimeInfrastructureService.infix_path, f"{c_hash}.content")

    def proc_descriptor_path(self, obj_id):
        return os.path.join(self._node.datastore(), RuntimeInfrastructureService.infix_path, f"{obj_id}.descriptor")

    def __init__(self, node, ssh_credentials: SSHCredentials = None):
        self._mutex = Lock()
        self._node = node
        self._deployed_processors = {}
        self._jobs_path = os.path.join(self._node.datastore(), 'jobs')
        self._content_keys = {}
        self._ssh_credentials = ssh_credentials

        # initialise directories
        subprocess.check_output(['mkdir', '-p', self._jobs_path])
        subprocess.check_output(['mkdir', '-p', os.path.join(self._node.datastore(),
                                                             RuntimeInfrastructureService.infix_path)])

        # initialise job id counter
        self._next_job_id = 0

    def rest_address(self):
        return self._node.rest.address()

    def get_job_wd(self, job_id=None):
        return os.path.join(self._jobs_path, job_id) if job_id else self._jobs_path

    def deploy(self, proc_id, deployment):
        with self._mutex:
            descriptor_path = self.proc_descriptor_path(proc_id)

            # is the processor already deployed?
            if proc_id in self._deployed_processors:
                return self._deployed_processors[proc_id].descriptor()

            # does any node in the network have the processor data object?
            # TODO: this is potentially redundant because when using the CLI, the node that has the processor
            #  is already known so no need to search for the right node.
            for network_node in self._node.db.get_network():
                # does the node have DOR?
                if network_node.dor_service is False:
                    continue

                # lookup the processor id
                proxy = DORProxy(network_node.rest_address.split(":"))
                descriptor = proxy.get_descriptor(proc_id)
                if descriptor:
                    content_path = self.proc_content_path(descriptor['c_hash'])
                    protocol = DataObjectRepositoryP2PProtocol(self._node)
                    protocol.send_fetch(network_node.p2p_address.split(":"), proc_id, descriptor_path, content_path)

                    proc_descriptor = descriptor['proc_descriptor']

                    # create an RTI adapter instance
                    if deployment == 'native':
                        # do we have a ssh profile to use?

                        self._deployed_processors[proc_id]: RTIProcessorAdapter = \
                            RTINativeProcessorAdapter(proc_id, proc_descriptor, content_path, self._node,
                                                      ssh_credentials=self._ssh_credentials)

                    elif deployment == 'docker':
                        self._deployed_processors[proc_id]: RTIProcessorAdapter = \
                            RTIDockerProcessorAdapter(proc_id, proc_descriptor, content_path, self._node)

                    # start the processor and wait until it is deployed
                    processor = self._deployed_processors[proc_id]
                    processor.start()

                    return self._deployed_processors[proc_id].descriptor()

            return None

    def undeploy(self, proc_id):
        with self._mutex:
            if proc_id in self._deployed_processors:
                # TODO: what happens with pending jobs???

                # stop the processor and wait for shutdown to complete
                processor = self._deployed_processors[proc_id]
                processor.stop()
                processor.join()

                # remove the processor
                self._deployed_processors.pop(proc_id)

                return processor
            else:
                return None

    def is_deployed(self, proc_id):
        with self._mutex:
            return proc_id in self._deployed_processors

    def get_deployed(self):
        with self._mutex:
            return [*self._deployed_processors]

    def get_descriptor(self, proc_id):
        with self._mutex:
            return self._deployed_processors[proc_id].descriptor() if proc_id in self._deployed_processors else None

    def submit(self, proc_id, descriptor):
        with self._mutex:
            # get the processor for that job
            processor = self._deployed_processors[proc_id]
            if not processor:
                return None

            # determine job id
            job_id = str(self._next_job_id)
            self._next_job_id += 1

            # create job descriptor
            job_descriptor = {
                'id': job_id,
                'proc_id': proc_id,
                'descriptor': descriptor
            }

            # create working directory
            wd_path = os.path.join(self._jobs_path, str(job_descriptor['id']))
            subprocess.check_output(['mkdir', '-p', wd_path])

            # dump the job descriptor
            job_descriptor_path = os.path.join(wd_path, 'job_descriptor.json')
            write_json_to_file(job_descriptor, job_descriptor_path)

            # create status logger
            status_path = os.path.join(wd_path, 'job_status.json')
            status = StatusLogger(status_path)
            status.update_state(State.INITIALISED)

            # add it to the processor and the queue
            if processor.add(job_descriptor, status):
                return job_id

            else:
                return None

    def get_jobs(self, proc_id):
        with self._mutex:
            processor = self._deployed_processors[proc_id]
            return processor.get_pending()

    def get_job_info(self, job_id):
        with self._mutex:
            descriptor_path = os.path.join(self._jobs_path, str(job_id), 'job_descriptor.json')
            status_path = os.path.join(self._jobs_path, str(job_id), 'job_status.json')

            if not os.path.exists(descriptor_path) or not os.path.exists(status_path):
                return None

            with open(descriptor_path, 'r') as f:
                descriptor = json.load(f)

            with open(status_path, 'r') as f:
                status = json.load(f)

            return {
                'job_descriptor': descriptor,
                'status': status
            }

    def put_permission(self, req_id, content_key):
        with self._mutex:
            self._content_keys[req_id] = content_key

    def pop_permission(self, req_id):
        with self._mutex:
            return self._content_keys.pop(req_id, None)
