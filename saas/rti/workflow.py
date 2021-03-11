import time
import logging

from threading import Lock, Thread

from saas.eckeypair import ECKeyPair
from saas.rti.adapters import RTIProcessorAdapter
from saas.utilities.blueprint_helpers import request_rti_submit_task, request_rti_job_status

logger = logging.getLogger('RTI.workflow')


class TaskWrapper(Thread):
    def __init__(self, node, task_descriptor):
        super().__init__()
        self.mutex = Lock()
        self.node = node
        self.name = task_descriptor['name']
        self.proc_id = task_descriptor['processor_id']
        self.owner = ECKeyPair.from_public_key_string(task_descriptor['output']['owner_public_key'])
        self.input_interface = {}
        self.status = None
        self.dependencies = {}
        self.unresolved = {}

        self.is_done = False
        self.is_successful = False
        self.outputs = {}

        for input_descriptor in task_descriptor['input']:
            key = input_descriptor['name']
            self.input_interface[key] = input_descriptor

            if input_descriptor['type'] == 'reference':
                obj_id = input_descriptor['obj_id']
                if obj_id.startswith('label'):
                    temp = obj_id.split(":")
                    label = f"{temp[1]}:{temp[2]}"
                    self.unresolved[label] = key
                    self.dependencies[key] = None
                else:
                    self.dependencies[key] = obj_id
            else:
                self.dependencies[key] = input_descriptor

    def run(self):
        try:
            # are all input data object dependencies resolved?
            self.mutex.acquire()
            while self.unresolved:
                self.mutex.release()
                time.sleep(1)
                self.mutex.acquire()
            self.mutex.release()

            # do we have the required processor deployed somewhere in the domain?
            address = self.find_processor_rest_api()
            while not address:
                time.sleep(60)
                address = self.find_processor_rest_api()

            # submit the job and wait until it's done
            job_id = request_rti_submit_task(address, self.node.key, self.owner, self.proc_id, self.input_interface)
            while True:
                time.sleep(5)
                job_descriptor, self.status = request_rti_job_status(address, self.node.key, self.proc_id, job_id)
                if self.status['status'] != 'running':
                    break

            # extract the object ids for the output data objects (i.e., the products of the task)
            for item in self.status.items():
                if item[0].startswith("output:"):
                    temp = item[0].split(":")
                    self.outputs[temp[1]] = item[1]

            self.is_successful = True

        except Exception as e:
            logger.error(f"error while executing task wrapper: {e}")
            self.is_successful = False

        self.is_done = True

    def find_processor_rest_api(self):
        records = self.node.registry.get()
        for node_iid in records:
            record = records[node_iid]
            if self.proc_id in record['processors']:
                return record['rest_api_address']
        return None

    def has_unresolved_dependencies(self):
        return self.unresolved

    def resolve(self, key, obj_id):
        if key in self.unresolved:
            key2 = self.unresolved.pop(key)
            self.input_interface[key2]['obj_id'] = obj_id
            self.dependencies[key2] = obj_id


class RTIWorkflowProcessorAdapter(RTIProcessorAdapter):
    def __init__(self, rti):
        super().__init__('workflow', rti)

    def execute(self, workflow_descriptor, working_directory, status):
        status.update('status', 'running')

        pending = {}
        finished = {}

        # initialise pending tasks
        status.update('stage', 'initialise pending tasks')
        for task in workflow_descriptor['tasks']:
            wrapper = TaskWrapper(self.rti.node, task)
            wrapper.start()
            pending[wrapper.name] = wrapper

        # waiting for pending tasks to be done
        status.update('stage', 'waiting for pending tasks')
        resolved = {}
        success = True
        while pending:
            pacing = True
            for name in pending:
                wrapper = pending[name]
                if wrapper.is_done:
                    pending.pop(name)
                    finished[name] = wrapper

                    for output_name in wrapper.outputs:
                        label = f"{wrapper.name}:{output_name}"
                        resolved[label] = wrapper.outputs[output_name]

                    # if the task was unsuccessful, take note of it
                    if not wrapper.is_successful:
                        success = False

                    pacing = False
                    break

                else:
                    for key in resolved:
                        wrapper.resolve(key, resolved[key])

            if pacing:
                time.sleep(1)

        # collect the output data object ids
        status.update('stage', 'collecting outputs')
        for output_name in resolved:
            status.update(f"output:{output_name}", resolved[output_name])

        status.remove_all(['stage'])
        return success

