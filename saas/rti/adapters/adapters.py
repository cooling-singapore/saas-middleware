import json
import logging
import os
import time
from abc import abstractmethod
from enum import Enum
from threading import Lock, Thread
from typing import Optional

from saas.cryptography.helpers import encrypt_file, decrypt_file
from saas.cryptography.keypair import KeyPair
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.dor.blueprint import DORProxy
from saas.dor.exceptions import IdentityNotFoundError
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.exceptions import SaaSException
from saas.keystore.identity import Identity
from saas.p2p.exceptions import PeerUnavailableError
from saas.rti.exceptions import ProcessorNotAcceptingJobsError, UnresolvedInputDataObjectsError, \
    AccessNotPermittedError, MissingUserSignatureError, MismatchingDataTypeOrFormatError, InvalidJSONDataObjectError
from saas.rti.status import State, StatusLogger
from saas.helpers import write_json_to_file, read_json_from_file, generate_random_string, create_symbolic_link, \
    validate_json

logger = logging.getLogger('rti.adapters')


class ProcessorState(Enum):
    UNINITIALISED = 'uninitialised'
    STARTING = 'starting'
    WAITING = 'waiting'
    BUSY = 'busy'
    STOPPING = 'stopping'
    STOPPED = 'stopped'


class RTIProcessorAdapter(Thread):
    def __init__(self, proc_id: str, proc_descriptor: dict, job_wd_path: str, node):
        Thread.__init__(self, daemon=True)

        self._mutex = Lock()
        self._proc_id = proc_id
        self._proc_descriptor = proc_descriptor
        self._job_wd_path = job_wd_path
        self._node = node

        self._input_interface = {item['name']: item for item in proc_descriptor['input']}
        self._output_interface = {item['name']: item for item in proc_descriptor['output']}
        self._pending = []
        self._state = ProcessorState.UNINITIALISED

    @property
    def id(self) -> str:
        return self._proc_id

    @property
    def descriptor(self) -> dict:
        return self._proc_descriptor

    @property
    def state(self) -> ProcessorState:
        return self._state

    @abstractmethod
    def startup(self) -> None:
        pass

    @abstractmethod
    def shutdown(self) -> None:
        pass

    @abstractmethod
    def execute(self, job_descriptor: dict, working_directory: str, status: StatusLogger) -> None:
        pass

    def stop(self) -> None:
        logger.info(f"[adapter:{self._proc_id}] received stop signal.")
        self._state = ProcessorState.STOPPING

    def pre_execute(self, task_descriptor: dict, working_directory: str, status: StatusLogger) -> None:
        # store by-value input data objects (if any)
        self._store_value_input_data_objects(task_descriptor, working_directory, status)

        # lookup by-reference input data objects (if any)
        obj_records = self._lookup_reference_input_data_objects(task_descriptor, status)

        # fetch by-reference input data objects (if any)
        ephemeral_key = RSAKeyPair.create_new()
        pending_content_keys = self._fetch_reference_input_data_objects(ephemeral_key, task_descriptor, obj_records,
                                                                        working_directory, status)

        # decrypt by-reference input data objects (if any)
        self._decrypt_reference_input_data_objects(ephemeral_key, pending_content_keys, status)

        # verify that data types of input data objects match
        self._verify_input_data_objects_types_and_formats(task_descriptor, working_directory, status)

        # verify the output owner identities
        self._verify_output_data_object_owner_identities(task_descriptor, status)

    def post_execute(self, task_descriptor: dict, working_directory: str, job_id: str, status: StatusLogger) -> None:
        # push output data objects to DOR
        self._push_output_data_objects(task_descriptor, working_directory, job_id, status)

    def add(self, job_descriptor: dict, status: StatusLogger) -> None:
        with self._mutex:
            # are we accepting jobs?
            if self._state == ProcessorState.STOPPING or self._state == ProcessorState.STOPPED:
                raise ProcessorNotAcceptingJobsError({
                    'proc_id': self._proc_id,
                    'job_descriptor': job_descriptor
                })

            self._pending.append((job_descriptor, status))

    def pending_jobs(self) -> list[dict]:
        with self._mutex:
            return [job_descriptor for job_descriptor, _ in self._pending]

    def run(self) -> None:
        logger.info(f"[adapter:{self._proc_id}] starting up...")
        self._state = ProcessorState.STARTING
        self.startup()

        logger.info(f"[adapter:{self._proc_id}] started.")
        while self._state != ProcessorState.STOPPING and self._state != ProcessorState.STOPPED:
            # wait for a pending job (or for adapter to become inactive)
            self._state = ProcessorState.WAITING
            pending_job = self._wait_for_pending_job()
            if not pending_job:
                break

            # process a job
            self._state = ProcessorState.BUSY
            job_descriptor = pending_job[0]
            status = pending_job[1]

            # set job state
            status.update_state(State.RUNNING)

            try:
                job_id = str(job_descriptor['id'])
                task_descriptor = job_descriptor['task']
                wd_path = os.path.join(self._job_wd_path, job_id)

                # perform pre-execute routine
                self.pre_execute(task_descriptor, wd_path, status)

                # instruct processor adapter to execute the job
                self.execute(task_descriptor, wd_path, status)

                # perform post-execute routine
                self.post_execute(task_descriptor, wd_path, job_id, status)

                status.update_state(State.SUCCESSFUL)

            except SaaSException as e:
                status.update('error', f"error while running job:\n"
                                       f"id: {e.id}\n"
                                       f"reason: {e.reason}\n"
                                       f"details: {e.details}")
                status.update_state(State.FAILED)

        logger.info(f"[adapter:{self._proc_id}] shutting down...")
        self._state = ProcessorState.STOPPING
        self._purge_pending_jobs()
        self.shutdown()

        logger.info(f"[adapter:{self._proc_id}] shut down.")
        self._state = ProcessorState.STOPPED

    def _wait_for_pending_job(self) -> Optional[tuple[dict, StatusLogger]]:
        while True:
            with self._mutex:
                # if the adapter has become inactive, return immediately.
                if self._state == ProcessorState.STOPPING or self._state == ProcessorState.STOPPED:
                    return None

                # if there is a job, return it
                elif len(self._pending) > 0:
                    job_descriptor, status = self._pending.pop(0)
                    return job_descriptor, status

            time.sleep(0.1)

    def _purge_pending_jobs(self) -> None:
        with self._mutex:
            while len(self._pending) > 0:
                job_descriptor, status = self._pending.pop(0)
                logger.info(f"purged pending job: {job_descriptor}")

    def _lookup_reference_input_data_objects(self, task_descriptor: dict, status: StatusLogger) -> dict:
        status.update('step', f"lookup by-reference input data objects")

        # do we have any by-reference input data objects in the first place?
        pending = {item['obj_id']: item['user_signature'] if 'user_signature' in item else None
                   for item in task_descriptor['input'] if item['type'] == 'reference'}
        if len(pending) == 0:
            return {}

        # get the user identity
        user = self._node.db.get_identity(task_descriptor['user_iid'])
        if user is None:
            raise IdentityNotFoundError(task_descriptor['user_iid'])

        # lookup all referenced data objects using the P2P protocol
        protocol = DataObjectRepositoryP2PProtocol(self._node)
        found = {}
        for peer in self._node.db.get_network_all():
            # only check with peers that have a DOR
            if peer['dor_service']:
                try:
                    # does the remote DOR have the data object?
                    records = protocol.lookup(peer['p2p_address'], [*pending.keys()], user)
                    for obj_id, record in records.items():
                        found[obj_id] = record
                        found[obj_id]['custodian'] = peer
                        found[obj_id]['user_signature'] = pending[obj_id]
                        pending.pop(obj_id)

                    # still pending object ids? if not, we are done.
                    if len(pending) == 0:
                        break

                # ignore peers that are not available
                except PeerUnavailableError:
                    continue

        # do we still have pending data objects?
        if len(pending) > 0:
            raise UnresolvedInputDataObjectsError({
                'pending': pending,
                'found': found
            })

        # check if the user has access permissions and if we have user signatures for all restricted data objects
        for obj_id, item in found.items():
            if item['access_restricted']:
                if not item['user_has_permission']:
                    raise AccessNotPermittedError({
                        'obj_id': obj_id,
                        'user_iid': user.id
                    })

                if 'user_signature' not in item:
                    raise MissingUserSignatureError({
                        'obj_id': obj_id,
                        'user_iid': user.id
                    })

        return found

    def _fetch_reference_input_data_objects(self, ephemeral_key: KeyPair, task_descriptor: dict, obj_records: dict,
                                            working_directory: str, status: StatusLogger) -> list[dict]:

        status.update('step', f"fetch by-reference input data objects")

        # do we have any data objects to fetch to begin with?
        if len(obj_records) == 0:
            return []

        # get the user identity
        user = self._node.db.get_identity(task_descriptor['user_iid'])
        if user is None:
            raise IdentityNotFoundError(task_descriptor['user_iid'])

        # fetch input data objects one by one using the P2P protocol
        protocol = DataObjectRepositoryP2PProtocol(self._node)
        pending_content_keys = []
        for obj_id, record in obj_records.items():
            descriptor_path = os.path.join(working_directory, f"{obj_id}.descriptor")
            content_path = os.path.join(working_directory, f"{obj_id}.content")

            # fetch the data object
            protocol.fetch(record['custodian']['p2p_address'], obj_id, descriptor_path, content_path,
                           task_descriptor['user_iid'] if record['access_restricted'] else None,
                           record['user_signature'] if record['access_restricted'] else None)

            # is the data object content encrypted? if yes, then we need to request the content key
            if record['content_encrypted']:
                # get the owner identity
                owner = self._node.db.get_identity(record['owner_iid'])
                if owner is None:
                    raise IdentityNotFoundError(record['owner_iid'])

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
                self._node.email.send_content_key_request(owner, obj_id, user, node_address, request)

                pending_content_keys.append({
                    'req_id': req_id,
                    'obj_id': obj_id,
                    'path': content_path
                })

        # create symbolic links to the contents for every input
        for item in task_descriptor['input']:
            if item['type'] == 'reference':
                create_symbolic_link(item['name'], f"{item['obj_id']}.content",
                                     working_directory=working_directory)

                create_symbolic_link(f"{item['name']}.descriptor", f"{item['obj_id']}.descriptor",
                                     working_directory=working_directory)

        return pending_content_keys

    def _decrypt_reference_input_data_objects(self, ephemeral_key: KeyPair, pending_content_keys: list[dict],
                                              status: StatusLogger) -> None:
        status.update('step', f"decrypt by-reference input data objects")

        while len(pending_content_keys) > 0:
            need_sleep = True
            for item in pending_content_keys:
                # have we received the permission for this request?
                permission = self._node.rti.pop_permission(item['req_id'])
                if permission is not None:
                    need_sleep = False

                    # decrypt the content key
                    content_key = ephemeral_key.decrypt(permission.encode('utf-8'), base64_encoded=True)

                    # decrypt the data object using the
                    decrypt_file(item['path'], content_key)

                    pending_content_keys.remove(item)
                    break

            if need_sleep:
                time.sleep(1)

    def push_output_data_object(self, output_descriptor: dict, output_content_path: str, owner: Identity,
                                task_descriptor: dict, job_id: str, status: StatusLogger) -> Optional[str]:
        output_name = output_descriptor['name']
        data_type = output_descriptor['data_type']
        data_format = output_descriptor['data_format']
        created_by = self._node.identity().id

        status.update('step', f"push output data object {output_name}")

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
                    node_record = self._node.db.get_network(item['target_node_iid'])

                    # extract the rest address from that node record
                    target_address = node_record['rest_address']

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
                    'job_id': job_id,
                    'data-type': data_type,
                    'data-format': data_format
                })

                # transfer ownership to the new owner
                proxy.transfer_ownership(obj_id, self._node.keystore, owner)

                return obj_id

        return None

    def _store_value_input_data_objects(self, task_descriptor: dict, working_directory: str, status: StatusLogger):
        status.update('step', f"store by-value input data objects")

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

    def _verify_input_data_objects_types_and_formats(self, task_descriptor: dict, working_directory: str,
                                                     status: StatusLogger) -> None:
        status.update('step', 'verify input data object types and formats')

        for item in task_descriptor['input']:
            obj_name = item['name']

            # check if data type/format indicated in processor descriptor and data object descriptor match
            d0 = read_json_from_file(os.path.join(working_directory, f"{obj_name}.descriptor"))
            d1 = self._input_interface[obj_name]
            if d0['data_type'] != d1['data_type'] or d0['data_format'] != d1['data_format']:
                raise MismatchingDataTypeOrFormatError({
                    'obj_name': obj_name,
                    'expected': {
                        'data_type': d1['data_type'],
                        'data_format': d1['data_format']
                    },
                    'actual': {
                        'data_type': d0['data_type'],
                        'data_format': d0['data_format']
                    }
                })

            # in case of JSONObject data type, verify using the schema (if any)
            if d0['data_type'] == 'JSONObject' and 'schema' in d1:
                content = read_json_from_file(os.path.join(working_directory, obj_name))
                if not validate_json(content, d1['schema']):
                    raise InvalidJSONDataObjectError({
                        'obj_name': obj_name,
                        'content': content,
                        'schema': d1['schema']
                    })

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

            # is the output a JSONObject?
            if output_descriptor['data_type'] == 'JSONObject' and 'schema' in output_descriptor:
                content = read_json_from_file(output_content_path)
                if not validate_json(content, output_descriptor['schema']):
                    raise InvalidJSONDataObjectError({
                        'obj_name': output_name,
                        'content': content,
                        'schema': output_descriptor['schema']
                    })

            # push the output data object to the DOR
            obj_id = self.push_output_data_object(output_descriptor, output_content_path, owner,
                                                  task_descriptor, job_id, status)
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
