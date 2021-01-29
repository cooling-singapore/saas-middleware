__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import os
import logging
import copy
import subprocess
import json

from threading import Lock

from saas.rti.adapters import RTIDockerProcessorAdapter, RTIPackageProcessorAdapter
from saas.rti.workflow import RTIWorkflowProcessorAdapter
from saas.rti.adapters import RTIScriptProcessorAdapter, RTIProcessorAdapter

from jsonschema import validate, ValidationError


logger = logging.getLogger('RTI')


def validate_json(instance, schema):
    try:
        validate(instance=instance, schema=schema)
        return True

    except ValidationError:
        return False


class RuntimeInfrastructure:
    workflow_proc_id = 'workflow'

    def __init__(self, node, support_workflows=True):
        self.mutex = Lock()
        self.node = node
        self.deployed_processors = {}

        # create working directories
        self.jobs_path = os.path.join(self.node.datastore_path, 'jobs')
        subprocess.check_output(['mkdir', '-p', self.jobs_path])

        # initialise job id counter
        self.next_job_id = 0

        if support_workflows:
            # start the workflow adapter
            adapter: RTIProcessorAdapter = RTIWorkflowProcessorAdapter(self)
            self.deployed_processors = {
                RuntimeInfrastructure.workflow_proc_id: adapter
            }
            adapter.start()

    def deploy(self, proc_id):
        self.mutex.acquire()

        # is the processor already deployed?
        descriptor_path = self.node.dor.obj_descriptor_path(proc_id, cache=True)
        if proc_id in self.deployed_processors:
            # load the descriptor
            with open(descriptor_path) as f:
                descriptor = json.load(f)

                self.mutex.release()
                return descriptor

        # do we have a processor image/package?
        c_hash = self.node.dor.fetch(proc_id)
        if not c_hash:
            self.mutex.release()
            return None

        # load the descriptor
        with open(descriptor_path) as f:
            descriptor = json.load(f)

        # create an RTI adapter
        content_path = self.node.dor.obj_content_path(c_hash, cache=True)
        if descriptor['type'] == 'docker':
            self.deployed_processors[proc_id]: RTIProcessorAdapter = RTIDockerProcessorAdapter(descriptor,
                                                                                               content_path,
                                                                                               self)

        elif descriptor['type'] == 'package':
            self.deployed_processors[proc_id]: RTIProcessorAdapter = RTIPackageProcessorAdapter(descriptor,
                                                                                                content_path,
                                                                                                self)

        elif descriptor['type'] == 'script':
            self.deployed_processors[proc_id]: RTIProcessorAdapter = RTIScriptProcessorAdapter(proc_id,
                                                                                               content_path,
                                                                                               self)

        self.deployed_processors[proc_id].start()

        # update registry
        self.node.registry.add_processor(proc_id)

        self.mutex.release()
        return descriptor

    def undeploy(self, proc_id, force=False):
        self.mutex.acquire()
        if proc_id in self.deployed_processors:
            # TODO: what happens with pending jobs???
            processor = self.deployed_processors[proc_id]
            processor.stop()
            self.deployed_processors.pop(proc_id)

            # update registry
            self.node.registry.remove_processor(proc_id)

            self.mutex.release()
            return processor
        else:
            self.mutex.release()
            return None

    def is_deployed(self, proc_id):
        self.mutex.acquire()
        result = proc_id in self.deployed_processors
        self.mutex.release()
        return result

    def get_deployed(self):
        self.mutex.acquire()
        result = [*self.deployed_processors]
        self.mutex.release()
        return result

    def get_descriptor(self, proc_id):
        descriptor_path = self.node.dor.obj_descriptor_path(proc_id, cache=True)
        with open(descriptor_path) as f:
            return json.load(f)

    def submit(self, proc_id, descriptor):
        self.mutex.acquire()

        # get the processor for that job
        processor = self.deployed_processors[proc_id]
        if not processor:
            self.mutex.release()
            return None

        # determine job id
        job_id = self.next_job_id
        self.next_job_id += 1

        # create job descriptor
        job_descriptor = {
            'id': job_id,
            'proc_id': proc_id,
            'descriptor': descriptor
        }

        # add it to the processor and the queue
        if processor.add(job_descriptor):
            self.mutex.release()
            return job_id

        else:
            self.mutex.release()
            return None

    def get_jobs(self, proc_id):
        self.mutex.acquire()
        processor = self.deployed_processors[proc_id]
        if processor:
            result = copy.deepcopy(processor.pending)
        else:
            result = None
        self.mutex.release()
        return result

    def get_job(self, job_id):
        self.mutex.acquire()

        descriptor_path = os.path.join(self.jobs_path, job_id, 'job_descriptor.json')
        status_path = os.path.join(self.jobs_path, job_id, 'job_status.json')

        if not os.path.exists(descriptor_path) or not os.path.exists(status_path):
            self.mutex.release()
            return None

        with open(descriptor_path, 'r') as f:
            descriptor = json.load(f)

        with open(status_path, 'r') as f:
            status = json.load(f)

        self.mutex.release()
        return {
            'job_descriptor': descriptor,
            'status': status
        }

