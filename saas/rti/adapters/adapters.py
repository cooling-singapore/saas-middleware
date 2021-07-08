import importlib
import logging
import os
import subprocess
import time
from threading import Lock, Thread

from saas.cryptography.helpers import encrypt_file
from saas.dor.blueprint import DORProxy
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.rti.status import State
from saas.utilities.general_helpers import dump_json_to_file, load_json_from_file

logger = logging.getLogger('rti.adapters')


def import_with_auto_install(package):
    try:
        return importlib.import_module(package)

    except ImportError:
        # pip.main doesn't seem to work on a GCE instance, call python3 directly instead
        # pip.main(['install', package])
        subprocess.check_output(['python3', '-m', 'pip', 'install', package])

    return importlib.import_module(package)


class RTIProcessorAdapter(Thread):
    def __init__(self, proc_id, node):
        Thread.__init__(self, daemon=True)

        self._node = node
        self._proc_id = proc_id
        self._mutex = Lock()
        self._pending = []
        self._is_active = True

    def startup(self):
        return True

    def shutdown(self):
        return True

    def pre_execute(self, task_or_wf_descriptor, working_directory, status):
        return True

    def post_execute(self, task_or_wf_descriptor, working_directory, status):
        return True

    def execute(self, job_descriptor, working_directory, status):
        pass

    def add(self, job_descriptor, status):
        with self._mutex:
            if self._is_active:
                self._pending.append((job_descriptor, status))
                return True
            else:
                return False

    def get_pending(self):
        with self._mutex:
            return [job_descriptor for job_descriptor, _ in self._pending]

    def stop(self):
        logger.info(f"adapter {self._proc_id} received stop signal.")
        self._is_active = False

    def _wait_for_pending_job(self):
        while True:
            with self._mutex:
                # if the adapter has become inactive, return immediately.
                if not self._is_active:
                    return None

                # if there is a job, return it
                elif len(self._pending) > 0:
                    job_descriptor, status = self._pending.pop(0)
                    return [job_descriptor, status]

            time.sleep(0.2)

    def run(self):
        logger.info(f"adapter {self._proc_id} starting up...")
        self.startup()

        logger.info(f"adapter {self._proc_id} started up.")
        while self._is_active:
            # wait for a pending job (or for adapter to become inactive)
            result = self._wait_for_pending_job()
            if not result:
                break

            job_descriptor = result[0]
            status = result[1]

            # perform pre-execute routine
            task_or_wf_descriptor = job_descriptor['descriptor']
            wd_path = self._node.rti.get_job_wd(str(job_descriptor['id']))
            if not self.pre_execute(task_or_wf_descriptor, wd_path, status):
                status.update_state(State.FAILED)
                continue

            # instruct processor adapter to execute the job
            if not self.execute(task_or_wf_descriptor, wd_path, status):
                status.update_state(State.FAILED)
                continue

            # perform post-execute routine
            if not self.post_execute(task_or_wf_descriptor, wd_path, status):
                status.update_state(State.FAILED)
                continue

            status.update_state(State.SUCCESSFUL)

        logger.info(f"adapter {self._proc_id} shutting down...")
        self.shutdown()

        logger.info(f"adapter {self._proc_id} shut down.")

    def push_output_data_object(self, output_descriptor, output_content_path, owner, task_descriptor):
        output_name = output_descriptor['name']
        data_type = output_descriptor['data_type']
        data_format = output_descriptor['data_format']
        created_by = owner.id()

        for item in task_descriptor['output']:
            if item['name'] == output_name:
                restricted_access = item['restricted_access']
                content_encrypted = item['content_encrypted']
                content_key = None

                if content_encrypted:
                    # encrypt the content and set the content key
                    content_key = encrypt_file(output_content_path,
                                               protect_key_with=owner.encryption_public_key(),
                                               delete_source=True)

                # upload the data object to the DOR
                proxy = DORProxy(self._node.rest.address(), self._node)
                obj_id, _ = proxy.add_data_object(output_content_path, owner,
                                                  restricted_access, content_encrypted, content_key,
                                                  data_type, data_format, created_by,
                                                  recipe=proxy.create_recipe(task_descriptor, output_name))

                return obj_id

        return None


class RTITaskProcessorAdapter(RTIProcessorAdapter):
    def __init__(self, proc_id, node):
        super().__init__(proc_id, node)

        self._input_interface = {}
        self._output_interface = {}

    def parse_io_interface(self, descriptor):
        for item in descriptor['input']:
            self._input_interface[item['name']] = item

        for item in descriptor['output']:
            self._output_interface[item['name']] = item

    def _store_value_input_data_objects(self, task_descriptor, working_directory, status):
        status.update('input_status', f"storing value data objects")
        for item in task_descriptor['input']:
            obj_name = item['name']

            # if it is a 'value' input then store it to the working directory
            if item['type'] == 'value':
                input_content_path = os.path.join(working_directory, obj_name)
                dump_json_to_file(item['value'], input_content_path)
                dump_json_to_file({
                    'data_type': 'JSONObject',
                    'data_format': 'json'
                }, f"{input_content_path}.descriptor")

        status.remove('input_status')
        return True

    def _fetch_reference_input_data_objects(self, task_descriptor, working_directory, status):
        status.update('input_status', f"fetching data objects")

        # get the user identity
        user = self._node.db.get_identity(task_descriptor['user_iid'])
        if user is None:
            error = f"could not find user identity: iid={task_descriptor['user_iid']}"
            logger.error(error)
            status.update('error', error)
            return False

        # initialise summary for referenced data objects
        names = {}
        missing = {}
        for item in task_descriptor['input']:
            if item['type'] == 'reference':
                obj_name = item['name']
                obj_id = item['obj_id']
                names[obj_id] = obj_name

                missing[obj_id] = item['user_signature'] if 'user_signature' in item else None

        found = {}
        if len(missing) > 0:
            # search the network for the data objects
            network = self._node.db.get_network()
            for node in network:
                peer_address = node.p2p_address.split(":")
                result = self._node.dor.protocol.send_lookup(peer_address, missing, user)

                # move found items to the result set and remove from the pending set
                for obj_id in result:
                    found[obj_id] = result[obj_id]
                    found[obj_id]['name'] = names[obj_id]
                    found[obj_id]['user_signature'] = missing.pop(obj_id)

                # if we have no more pending items, stop the search
                if len(missing) == 0:
                    break

        # do we still have missing data objects?
        if len(missing) > 0:
            error = f"could not find data objects: {missing}"
            logger.error(error)
            status.update('error', error)
            return False

        # check if the user has access permissions and if we have user signatures for all restricted data objects
        for obj_id, item in found.items():
            if item['access_restricted']:
                if not item['user_has_permission']:
                    error = f"user does not have access permission for restricted object: {obj_id}"
                    logger.error(error)
                    status.update('error', error)
                    return False

                if 'user_signature' not in item:
                    error = f"no user signature found for restricted object: {obj_id}"
                    logger.error(error)
                    status.update('error', error)
                    return False

        # fetch all references data objects
        protocol = DataObjectRepositoryP2PProtocol(self._node)
        for obj_id, item in found.items():
            destination_descriptor_path = os.path.join(working_directory, f"{item['name']}.descriptor")
            destination_content_path = os.path.join(working_directory, item['name'])

            # try to fetch the data object
            result = protocol.send_fetch(item['custodian_address'], obj_id,
                                         destination_descriptor_path, destination_content_path,
                                         user_iid=user.id(), user_signature=item['user_signature'])

            # if we the result is None, something went wrong...
            if result['code'] != 200:
                error = f"attempt to fetch data object {obj_id} failed. reason: {result['reason']}"
                logger.error(error)
                status.update('error', error)
                return False

        status.remove('input_status')
        return True

    def _verify_input_data_objects_types_and_formats(self, task_descriptor, working_directory, status):
        for item in task_descriptor['input']:
            obj_name = item['name']

            descriptor_path = os.path.join(working_directory, f"{obj_name}.descriptor")
            d0 = load_json_from_file(descriptor_path)
            d1 = self._input_interface[obj_name]

            if d0['data_type'] != d1['data_type'] or d0['data_format'] != d1['data_format']:

                error = f"mismatching type or format for input data object '{obj_name}': " \
                        f"processor_descriptor={(d1['data_type'], d1['data_format'])} " \
                        f"object_descriptor={(d0['data_type'], d0['data_format'])}"

                logger.error(error)
                status.update('error', error)
                return False

        return True

    def _verify_output_data_object_owner_identities(self, task_descriptor, status):
        for item in task_descriptor['output']:
            owner = self._node.db.get_identity(item['owner_iid'])
            if owner is None:
                error = f"could not find owner identity: iid={item['owner_iid']} " \
                        f"for output data object: name='{item['name']}'"
                logger.error(error)
                status.update('error', error)
                return False

        return True

    def pre_execute(self, task_descriptor, working_directory, status):
        # first, store 'value' input data objects to disk
        self._store_value_input_data_objects(task_descriptor, working_directory, status)

        # second, lookup 'reference' input data objects
        if not self._fetch_reference_input_data_objects(task_descriptor, working_directory, status):
            return False

        # third, verify that data types of input data objects match
        if not self._verify_input_data_objects_types_and_formats(task_descriptor, working_directory, status):
            return False

        # fourth, verify the output owner identities
        if not self._verify_output_data_object_owner_identities(task_descriptor, status):
            return False

        return True

    def post_execute(self, task_descriptor, working_directory, status):
        # push output data objects to DOR
        if not self._push_output_data_objects(task_descriptor, working_directory, status):
            return False

        return True

    def _push_output_data_objects(self, task_descriptor, working_directory, status):
        status.update('stage', 'push output data objects')

        # map the output items in the task descriptor
        output_items = {}
        for item in task_descriptor['output']:
            output_items[item['name']] = item

        successful = True
        for output_descriptor in self._output_interface.values():
            output_name = output_descriptor['name']

            output_content_path = os.path.join(working_directory, output_name)
            status.update_all({
                'output': output_descriptor,
                'output_content_path': output_content_path,
                'output_status': 'pending add'
            })

            # check if the output data object exists
            if not os.path.isfile(output_content_path):
                error = f"worker[{self.name}]: output data object '{output_name}' not available."
                logger.error(error)
                status.update('error', error)
                successful = False
                break

            # get the owner
            owner = self._node.db.get_identity(iid=output_items[output_name]['owner_iid'])
            if owner is None:
                error = f"could not find owner identity: iid={output_items[output_name]['owner_iid']} " \
                        f"for output data object: name='{output_name}'"
                logger.error(error)
                status.update('error', error)
                successful = False
                break

            # push the output data object to the DOR
            obj_id = self.push_output_data_object(output_descriptor, output_content_path, owner, task_descriptor)
            if not obj_id:
                error = f"worker[{self.name}]: failed to add data object '{output_descriptor['name']}'to DOR."
                logger.error(error)
                status.update('error', error)
                successful = False
                break

            status.update_all({
                f"output:{output_descriptor['name']}": obj_id,
                'output_status': 'added'
            })

        # clean up transient status information
        status.remove_all(['output', 'output_content_path', 'output_status'])
        return successful
