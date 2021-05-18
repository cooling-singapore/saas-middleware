import time
import logging
import traceback

from threading import Lock, Thread

from jsonschema import validate

from saas.cryptography.eckeypair import ECKeyPair
from saas.rti.adapters.adapters import RTIProcessorAdapter
from saas.rti.blueprint import RTIProxy
from saas.rti.status import State
from saas.schemas import task_descriptor_schema

logger = logging.getLogger('rti.workflow')


class TaskWrapper(Thread):
    def __init__(self, node, task_descriptor):
        Thread.__init__(self, name=task_descriptor['name'])
        self._mutex = Lock()
        self._node = node
        self._proxy = RTIProxy(node.rest.address(), node.identity())
        self._task_descriptor = task_descriptor
        self._input_interface = {}
        self._status = None
        self._dependencies = {}
        self._unresolved = {}

        self.is_done = False
        self.is_successful = False
        self._outputs = {}

        # validate the task descriptor and process it
        validate(instance=task_descriptor, schema=task_descriptor_schema)
        for input_descriptor in task_descriptor['input']:
            key = input_descriptor['name']
            self._input_interface[key] = input_descriptor

            if input_descriptor['type'] == 'reference':
                obj_id = input_descriptor['obj_id']
                if obj_id.startswith('label'):
                    temp = obj_id.split(":")
                    label = f"{temp[1]}:{temp[2]}"
                    self._unresolved[label] = key
                    self._dependencies[key] = None
                else:
                    self._dependencies[key] = obj_id
            else:
                self._dependencies[key] = input_descriptor

    def _wait_for_dependencies(self):
        while True:
            time.sleep(0.5)
            with self._mutex:
                if len(self._unresolved) == 0:
                    break

    def _wait_for_processor(self):
        while True:
            proc_id = self._task_descriptor['processor_id']

            network = self._node.db.get_network()
            for record in network:
                proxy = RTIProxy(record.rest_address.split(":"), self._node.identity())
                deployed = proxy.get_deployed()
                if proc_id in deployed:
                    return

            time.sleep(60)

    def _submit_and_wait_for_task(self):
        proc_id = self._task_descriptor['processor_id']
        owner = ECKeyPair.from_public_key_string(self._task_descriptor['output']['owner_public_key'])
        job_id = self._proxy.submit_task(proc_id, self._input_interface, owner)
        while True:
            time.sleep(5)
            _, self._status = self._proxy.get_job_info(proc_id, job_id)

            state = State.from_string(self._status['state'])
            if state in [State.FAILED, State.SUCCESSFUL]:
                break

    def _extract_outputs(self):
        with self._mutex:
            for item in self._status.items():
                if item[0].startswith("output:"):
                    temp = item[0].split(":")
                    self._outputs[temp[1]] = item[1]

    def run(self):
        try:
            # are all input data object dependencies resolved?
            self._wait_for_dependencies()

            # do we have the required processor deployed somewhere in the domain?
            self._wait_for_processor()

            # submit the job and wait until it's done
            self._submit_and_wait_for_task()

            # extract the object ids for the output data objects (i.e., the products of the task)
            self._extract_outputs()

            self.is_successful = True

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            logger.error(f"error while executing task wrapper: {e}, trace={trace}")
            self.is_successful = False

        self.is_done = True

    # def has_unresolved_dependencies(self):
    #     with self._mutex:
    #         return len(self._unresolved) > 0

    def resolve(self, key, obj_id):
        with self._mutex:
            if key in self._unresolved:
                key2 = self._unresolved.pop(key)
                self._input_interface[key2]['obj_id'] = obj_id
                self._dependencies[key2] = obj_id

    def get_outputs(self):
        with self._mutex:
            return self._outputs


class RTIWorkflowProcessorAdapter(RTIProcessorAdapter):
    def __init__(self, node):
        RTIProcessorAdapter.__init__(self, 'workflow', node)

        self._node = node

    def execute(self, workflow_descriptor, working_directory, status):
        status.update_state(State.RUNNING)

        pending = {}
        finished = {}

        # initialise pending tasks
        status.update('stage', 'initialise pending tasks')
        for task in workflow_descriptor['tasks']:
            wrapper = TaskWrapper(self._node, task)
            pending[wrapper.name] = wrapper
            wrapper.start()

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

                    outputs = wrapper.get_outputs()
                    for output_name in outputs:
                        label = f"{wrapper.name}:{output_name}"
                        resolved[label] = outputs[output_name]

                    # if the task was unsuccessful, take note of it
                    if not wrapper.is_successful:
                        success = False

                    pacing = False
                    break

                else:
                    for key in resolved:
                        wrapper.resolve(key, resolved[key])

            if pacing:
                time.sleep(0.1)

        # collect the output data object ids
        status.update('stage', 'collecting outputs')
        for output_name in resolved:
            status.update(f"output:{output_name}", resolved[output_name])

        status.remove_all(['stage'])
        return success

