import json
import logging
import os
import time
from enum import Enum
from threading import Lock, Thread
from typing import Optional

from saas.cryptography.helpers import encrypt_file, decrypt_file
from saas.cryptography.keypair import KeyPair
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.dor.blueprint import DORProxy
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.keystore.identity import Identity
from saas.rti.status import State, StatusLogger
from saas.helpers import write_json_to_file, read_json_from_file, generate_random_string

logger = logging.getLogger('rti.adapters')


class ProcessorState(Enum):
    UNINITIALISED = 'uninitialised'
    STARTING = 'starting'
    WAITING = 'waiting'
    BUSY = 'busy'
    STOPPING = 'stopping'
    STOPPED = 'stopped'


class RTIProcessorAdapter(Thread):
    def __init__(self, proc_id, proc_descriptor, node):
        Thread.__init__(self, daemon=True)

        self._node = node
        self._proc_id = proc_id
        self._proc_descriptor = proc_descriptor
        self._mutex = Lock()
        self._pending = []
        self._state = ProcessorState.UNINITIALISED

    def state(self):
        return self._state

    def descriptor(self):
        return self._proc_descriptor

    def startup(self):
        return True

    def shutdown(self):
        return True

    def pre_execute(self, task_or_wf_descriptor, working_directory, status):
        return True

    def post_execute(self, task_or_wf_descriptor, working_directory, job_id, status):
        return True

    def execute(self, job_descriptor, working_directory, status):
        pass

    def add(self, job_descriptor, status):
        with self._mutex:
            if self._state != ProcessorState.STOPPING and self._state != ProcessorState.STOPPED:
                self._pending.append((job_descriptor, status))
                return True
            else:
                return False

    def get_pending(self):
        with self._mutex:
            return [job_descriptor for job_descriptor, _ in self._pending]

    def stop(self):
        logger.info(f"adapter {self._proc_id} received stop signal.")
        self._state = ProcessorState.STOPPING

    def _wait_for_pending_job(self):
        while True:
            with self._mutex:
                # if the adapter has become inactive, return immediately.
                if self._state == ProcessorState.STOPPING or self._state == ProcessorState.STOPPED:
                    return None

                # if there is a job, return it
                elif len(self._pending) > 0:
                    job_descriptor, status = self._pending.pop(0)
                    return [job_descriptor, status]

            time.sleep(0.2)

    def run(self):
        logger.info(f"adapter {self._proc_id} starting up...")
        self._state = ProcessorState.STARTING
        self.startup()

        logger.info(f"adapter {self._proc_id} started up.")
        while self._state != ProcessorState.STOPPING and self._state != ProcessorState.STOPPED:
            # wait for a pending job (or for adapter to become inactive)
            self._state = ProcessorState.WAITING
            result = self._wait_for_pending_job()
            if not result:
                break

            # process a job
            self._state = ProcessorState.BUSY
            job_descriptor = result[0]
            status = result[1]

            # set job state
            status.update_state(State.RUNNING)

            # perform pre-execute routine
            job_id = str(job_descriptor['id'])
            task_or_wf_descriptor = job_descriptor['descriptor']
            wd_path = self._node.rti.get_job_wd(job_id)
            if not self.pre_execute(task_or_wf_descriptor, wd_path, status):
                status.update_state(State.FAILED)
                continue

            # instruct processor adapter to execute the job
            if not self.execute(task_or_wf_descriptor, wd_path, status):
                status.update_state(State.FAILED)
                continue

            # perform post-execute routine
            if not self.post_execute(task_or_wf_descriptor, wd_path, job_id, status):
                status.update_state(State.FAILED)
                continue

            status.update_state(State.SUCCESSFUL)

        logger.info(f"adapter {self._proc_id} shutting down...")
        self._state = ProcessorState.STOPPING
        self.shutdown()

        logger.info(f"adapter {self._proc_id} shut down.")
        self._state = ProcessorState.STOPPED

    def push_output_data_object(self, output_descriptor: dict, output_content_path: str, owner: Identity,
                                task_descriptor: dict, job_id: str) -> Optional[str]:
        output_name = output_descriptor['name']
        data_type = output_descriptor['data_type']
        data_format = output_descriptor['data_format']
        created_by = self._node.identity().id

        for item in task_descriptor['output']:
            if item['name'] == output_name:
                restricted_access = item['restricted_access']
                content_encrypted = item['content_encrypted']

                # TODO: figure out what is supposed to happen with the content key here
                content_key = encrypt_file(output_content_path, encrypt_for=owner,
                                           delete_source=True) if content_encrypted else None

                # do we have a target node specified for storing the data object?
                target_address = self._node.rest.address()
                if 'target_node_iid' in item:
                    # check with the node db to see if we know about this node
                    node_record = self._node.db.get_network_node(item['target_node_iid'])

                    # extract the rest address from that node record
                    target_address = node_record.rest_address.split(":")

                # upload the data object to the DOR (the owner is the node for now
                # so we can update tags in the next step)
                proxy = DORProxy(target_address)
                obj_id, _ = proxy.add_data_object(output_content_path, self._node.identity(),
                                                  restricted_access, content_encrypted,
                                                  data_type, data_format, created_by,
                                                  recipe={
                                                      'task_descriptor': task_descriptor,
                                                      'output_name': output_name
                                                  })

                # update tags with information from the job
                proxy.update_tags(obj_id, self._node.keystore, {
                    'name': f"{item['name']}",
                    'job_id': job_id
                })

                # transfer ownership to the new owner
                proxy.transfer_ownership(obj_id, self._node.keystore, owner)

                return obj_id

        return None


class RTITaskProcessorAdapter(RTIProcessorAdapter):
    def __init__(self, proc_id, proc_descriptor, node):
        super().__init__(proc_id, proc_descriptor, node)

        self._input_interface = {}
        self._output_interface = {}

        for item in proc_descriptor['input']:
            self._input_interface[item['name']] = item

        for item in proc_descriptor['output']:
            self._output_interface[item['name']] = item

    def _store_value_input_data_objects(self, task_descriptor: dict, working_directory: str, status: StatusLogger):
        status.update('input_status', f"storing value data objects")
        for item in task_descriptor['input']:
            obj_name = item['name']

            # if it is a 'value' input then store it to the working directory
            if item['type'] == 'value':
                input_content_path = os.path.join(working_directory, obj_name)
                write_json_to_file(item['value'], input_content_path)
                write_json_to_file({
                    'data_type': 'JSONObject',
                    'data_format': 'json'
                }, f"{input_content_path}.descriptor")

        status.remove('input_status')
        return True

    def _fetch_reference_input_data_objects(self, ephemeral_key: KeyPair, pending_list: list, task_descriptor: dict,
                                            working_directory: str, status: StatusLogger):
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
                                         user_iid=user.id, user_signature=item['user_signature'])

            # if the result is None, something went wrong...
            if result['code'] != 200:
                error = f"attempt to fetch data object {obj_id} failed. reason: {result['reason']}"
                logger.error(error)
                status.update('error', error)
                return False

            # is the data object content encrypted? if yes, then we need to request the content key
            if result['record']['content_encrypted']:
                # get the owner identity
                owner = self._node.db.get_identity(result['record']['owner_iid'])
                if owner is None:
                    error = f"could not find owner identity for data object: " \
                            f"iid={result['record']['owner_iid']} " \
                            f"obj_id={obj_id}"
                    logger.error(error)
                    status.update('error', error)
                    return False

                # create the request content and encrypt it using the owners key
                req_id = generate_random_string(16)
                node_address = self._node.rest.address()
                request = json.dumps({
                    'type': 'request_content_key',
                    'req_id': req_id,
                    'obj_id': obj_id,
                    'ephemeral_public_key': ephemeral_key.public_as_string(),
                    'user_name': user.name,
                    'user_email': user.email,
                    'node_id': self._node.identity().id,
                    'node_address': node_address
                })
                request = owner.encrypt(request.encode('utf-8')).decode('utf-8')

                # send an email to the owner
                if not self._node.email.send_content_key_request(owner, obj_id, user, node_address, request):
                    error = f"sending content key request failed."
                    logger.error(error)
                    status.update('error', error)
                    return False

                pending_list.append({
                    'req_id': req_id,
                    'obj_id': obj_id,
                    'path': destination_content_path
                })

        status.remove('input_status')
        return True

    def _decrypt_reference_input_data_objects(self, ephemeral_key: KeyPair, pending_list: list, status: StatusLogger):
        # wait for pending content keys (if any)
        status.update('input_status', f"decrypt input data objects")
        while len(pending_list) > 0:
            need_sleep = True
            for item in pending_list:
                # have we received the permission for this request?
                permission = self._node.rti.pop_permission(item['req_id'])
                if permission is not None:
                    need_sleep = False

                    # decrypt the content key
                    # content_key = ephemeral_key.decrypt(permission.encode('utf-8'), base64_encoded=True).decode('utf-8')
                    content_key = ephemeral_key.decrypt(permission.encode('utf-8'), base64_encoded=True)

                    # decrypt the data object using the
                    decrypt_file(item['path'], content_key)

                    pending_list.remove(item)
                    break

            if need_sleep:
                time.sleep(2)

        status.remove('input_status')
        return True

    def _verify_input_data_objects_types_and_formats(self, task_descriptor: dict, working_directory: str,
                                                     status: StatusLogger):
        for item in task_descriptor['input']:
            obj_name = item['name']

            descriptor_path = os.path.join(working_directory, f"{obj_name}.descriptor")
            d0 = read_json_from_file(descriptor_path)
            d1 = self._input_interface[obj_name]

            if d0['data_type'] != d1['data_type'] or d0['data_format'] != d1['data_format']:

                error = f"mismatching type or format for input data object '{obj_name}': " \
                        f"processor_descriptor={(d1['data_type'], d1['data_format'])} " \
                        f"object_descriptor={(d0['data_type'], d0['data_format'])}"

                logger.error(error)
                status.update('error', error)
                return False

        return True

    def _verify_output_data_object_owner_identities(self, task_descriptor: dict, status: StatusLogger):
        for item in task_descriptor['output']:
            owner = self._node.db.get_identity(item['owner_iid'])
            if owner is None:
                error = f"could not find owner identity: iid={item['owner_iid']} " \
                        f"for output data object: name='{item['name']}'"
                logger.error(error)
                status.update('error', error)
                return False

        return True

    def pre_execute(self, task_descriptor: dict, working_directory: str, status: StatusLogger):
        # store 'value' input data objects to disk
        self._store_value_input_data_objects(task_descriptor, working_directory, status)

        # fetch 'reference' input data objects
        ephemeral_key = RSAKeyPair.create_new()
        pending_list = []
        if not self._fetch_reference_input_data_objects(ephemeral_key, pending_list,
                                                        task_descriptor, working_directory, status):
            return False

        if not self._decrypt_reference_input_data_objects(ephemeral_key, pending_list, status):
            return False

        # third, verify that data types of input data objects match
        if not self._verify_input_data_objects_types_and_formats(task_descriptor, working_directory, status):
            return False

        # fourth, verify the output owner identities
        if not self._verify_output_data_object_owner_identities(task_descriptor, status):
            return False

        return True

    def post_execute(self, task_descriptor: dict, working_directory: str, job_id: str, status: StatusLogger):
        # push output data objects to DOR
        if not self._push_output_data_objects(task_descriptor, working_directory, job_id, status):
            return False

        return True

    def _push_output_data_objects(self, task_descriptor: dict, working_directory: str, job_id: str,
                                  status: StatusLogger):
        status.update('stage', 'push output data objects')

        # map the output items in the task descriptor
        output_items = {}
        for item in task_descriptor['output']:
            output_items[item['name']] = item

        successful = True
        output = []
        for output_descriptor in self._output_interface.values():
            output_name = output_descriptor['name']

            output_content_path = os.path.join(working_directory, output_name)
            status.update('pending_output_item', {
                'descriptor': output_descriptor,
                'content_path': output_content_path,
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
            obj_id = self.push_output_data_object(output_descriptor, output_content_path, owner,
                                                  task_descriptor, job_id)
            if not obj_id:
                error = f"worker[{self.name}]: failed to add data object '{output_descriptor['name']}'to DOR."
                logger.error(error)
                status.update('error', error)
                successful = False
                break

            output.append({
                'name': output_descriptor['name'],
                'obj_id': obj_id
            })

        # set the output data object ids
        status.update('output', output)

        # clean up transient status information
        status.remove('pending_output_item')
        return successful
