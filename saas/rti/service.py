__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import os
import logging
import subprocess
import json

from threading import Lock

from saas.rti.adapters import RTIDockerProcessorAdapter, RTIPackageProcessorAdapter
from saas.rti.workflow import RTIWorkflowProcessorAdapter
from saas.rti.status import StatusLogger, State
from saas.rti.adapters import RTIScriptProcessorAdapter, RTIProcessorAdapter

from jsonschema import validate, ValidationError

from saas.utilities.general_helpers import dump_json_to_file

logger = logging.getLogger('RTI')


def validate_json(instance, schema):
    try:
        validate(instance=instance, schema=schema)
        return True

    except ValidationError:
        return False


class RuntimeInfrastructureService:
    workflow_proc_id = 'workflow'

    def __init__(self, node, support_workflows=True):
        self._mutex = Lock()
        self._node = node
        self._deployed_processors = {}

        # create working directories
        self._jobs_path = os.path.join(self._node.datastore(), 'jobs')
        subprocess.check_output(['mkdir', '-p', self._jobs_path])

        # initialise job id counter
        self._next_job_id = 0

        if support_workflows:
            # start the workflow adapter
            adapter: RTIProcessorAdapter = RTIWorkflowProcessorAdapter(node)
            self._deployed_processors = {
                RuntimeInfrastructureService.workflow_proc_id: adapter
            }
            adapter.start()

    def rest_address(self):
        return self._node.rest.address()

    def get_job_wd(self, job_id=None):
        return os.path.join(self._jobs_path, job_id) if job_id else self._jobs_path

    def deploy(self, proc_id):
        with self._mutex:
            # is the processor already deployed?
            descriptor_path = self._node.dor.obj_descriptor_path(proc_id, cache=True)
            if proc_id in self._deployed_processors:
                # load the descriptor
                with open(descriptor_path) as f:
                    descriptor = json.load(f)
                    return descriptor

            # do we have a processor image/package?
            c_hash = self._node.dor.fetch(proc_id)
            if not c_hash:
                return None

            # load the descriptor
            with open(descriptor_path) as f:
                descriptor = json.load(f)

            # create an RTI adapter
            content_path = self._node.dor.obj_content_path(c_hash, cache=True)
            if descriptor['type'] == 'docker':
                self._deployed_processors[proc_id]: RTIProcessorAdapter = RTIDockerProcessorAdapter(proc_id,
                                                                                                    descriptor,
                                                                                                    content_path,
                                                                                                    self._node)

            elif descriptor['type'] == 'package':
                self._deployed_processors[proc_id]: RTIProcessorAdapter = RTIPackageProcessorAdapter(proc_id,
                                                                                                     descriptor,
                                                                                                     content_path,
                                                                                                     self._node)

            elif descriptor['type'] == 'script':
                self._deployed_processors[proc_id]: RTIProcessorAdapter = RTIScriptProcessorAdapter(proc_id,
                                                                                                    content_path,
                                                                                                    self._node)

            self._deployed_processors[proc_id].start()

            # update registry
            self._node.registry.add_processor(proc_id)

            return descriptor

    def undeploy(self, proc_id, force=False):
        with self._mutex:
            if proc_id in self._deployed_processors:
                # TODO: what happens with pending jobs???

                # stop the processor and wait for shutdown to complete
                processor = self._deployed_processors[proc_id]
                processor.stop()
                processor.join()

                # remove the processor
                self._deployed_processors.pop(proc_id)

                # update registry
                self._node.registry.remove_processor(proc_id)
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
        descriptor_path = self._node.dor.obj_descriptor_path(proc_id, cache=True)
        with open(descriptor_path) as f:
            return json.load(f)

    def submit(self, proc_id, descriptor):
        with self._mutex:
            # get the processor for that job
            processor = self._deployed_processors[proc_id]
            if not processor:
                return None

            # determine job id
            job_id = self._next_job_id
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
            dump_json_to_file(job_descriptor, job_descriptor_path)

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
            descriptor_path = os.path.join(self._jobs_path, job_id, 'job_descriptor.json')
            status_path = os.path.join(self._jobs_path, job_id, 'job_status.json')

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
