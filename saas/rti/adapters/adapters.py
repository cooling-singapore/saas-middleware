import json
import logging
import os
import time
from abc import abstractmethod, ABC
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
from saas.p2p.exceptions import PeerUnavailableError
from saas.rti.exceptions import ProcessorNotAcceptingJobsError, UnresolvedInputDataObjectsError, \
    AccessNotPermittedError, MissingUserSignatureError, MismatchingDataTypeOrFormatError, InvalidJSONDataObjectError, \
    DataObjectContentNotFoundError, DataObjectOwnerNotFoundError
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


class RTIProcessorAdapter(Thread, ABC):
    def __init__(self, proc_id: str, proc_descriptor: dict, job_wd_path: str, node) -> None:
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
    def execute(self, job_id: str, job_descriptor: dict, working_directory: str, status: StatusLogger) -> None:
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
        self._verify_inputs(task_descriptor, working_directory, status)

        # verify the output owner identities
        self._verify_outputs(task_descriptor, status)

    def post_execute(self, job_id: str, task_descriptor: dict, working_directory: str, status: StatusLogger) -> None:
        pass

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
            job_descriptor, status = pending_job

            # set job state
            status.update_state(State.RUNNING)

            job_id = str(job_descriptor['id'])
            task_descriptor = job_descriptor['task']
            wd_path = os.path.join(self._job_wd_path, job_id)

            try:
                # perform pre-execute routine
                self.pre_execute(task_descriptor, wd_path, status)

                # instruct processor adapter to execute the job
                self.execute(job_id, task_descriptor, wd_path, status)

                # perform post-execute routine
                self.post_execute(job_id, task_descriptor, wd_path, status)

            except SaaSException as e:
                status.update('error', f"error while running job:\n"
                                       f"id: {e.id}\n"
                                       f"reason: {e.reason}\n"
                                       f"details: {e.details}")
                status.update_state(State.FAILED)

            else:
                status.update_state(State.SUCCESSFUL)

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

    def _store_value_input_data_objects(self, task_descriptor: dict, working_directory: str,
                                        status: StatusLogger) -> None:
        status.update('step', f"store by-value input data objects")

        for item in task_descriptor['input']:
            # if it is a 'value' input then store it to the working directory
            if item['type'] == 'value':
                input_content_path = os.path.join(working_directory, item['name'])
                write_json_to_file(item['value'], input_content_path)
                write_json_to_file({
                    'data_type': 'JSONObject',
                    'data_format': 'json'
                }, f"{input_content_path}.descriptor")

    def _verify_inputs(self, task_descriptor: dict, working_directory: str, status: StatusLogger) -> None:
        status.update('step', 'verify inputs: data object types and formats')

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

    def _verify_outputs(self, task_descriptor: dict, status: StatusLogger) -> None:
        status.update('step', 'verify outputs: data object owner identities')

        for item in task_descriptor['output']:
            owner = self._node.db.get_identity(item['owner_iid'])
            if owner is None:
                raise DataObjectOwnerNotFoundError({
                    'output_name': item['name'],
                    'owner_iid': item['owner_iid']
                })

    def _push_data_object(self, job_id: str, obj_name: str, task_descriptor: dict, working_directory: str,
                          status: StatusLogger) -> None:

        # convenience variables
        task_out_items = {item['name']: item for item in task_descriptor['output']}
        task_out = task_out_items[obj_name]
        proc_out = self._output_interface[obj_name]

        # check if the output data object exists
        output_content_path = os.path.join(working_directory, obj_name)
        if not os.path.isfile(output_content_path):
            raise DataObjectContentNotFoundError({
                'output_name': obj_name,
                'content_path': output_content_path
            })

        # get the owner
        owner = self._node.db.get_identity(iid=task_out['owner_iid'])
        if owner is None:
            raise DataObjectOwnerNotFoundError({
                'output_name': obj_name,
                'owner_iid': task_out['owner_iid']
            })

        # is the output a JSONObject?
        if proc_out['data_type'] == 'JSONObject' and 'schema' in proc_out:
            content = read_json_from_file(output_content_path)
            if not validate_json(content, proc_out['schema']):
                raise InvalidJSONDataObjectError({
                    'obj_name': obj_name,
                    'content': content,
                    'schema': proc_out['schema']
                })

        restricted_access = task_out['restricted_access']
        content_encrypted = task_out['content_encrypted']

        # TODO: figure out what is supposed to happen with the content key here
        content_key = encrypt_file(output_content_path, encrypt_for=owner,
                                   delete_source=True) if content_encrypted else None

        # do we have a target node specified for storing the data object?
        target_address = self._node.rest.address()
        if 'target_node_iid' in task_out:
            # check with the node db to see if we know about this node
            node_record = self._node.db.get_network(task_out['target_node_iid'])

            # extract the rest address from that node record
            target_address = node_record['rest_address']

        # upload the data object to the DOR (the owner is the node for now
        # so we can update tags in the next step)
        proxy = DORProxy(target_address)
        meta = proxy.add_data_object(output_content_path, self._node.identity(), restricted_access, content_encrypted,
                                     proc_out['data_type'], proc_out['data_format'], self._node.identity().id,
                                     recipe={
                                         'task_descriptor': task_descriptor,
                                         'output_name': obj_name
                                     })
        obj_id = meta['obj_id']

        # update tags with information from the job
        proxy.update_tags(obj_id, self._node.keystore, {
            'name': f"{obj_name}",
            'job_id': job_id,
            'data-type': proc_out['data_type'],
            'data-format': proc_out['data_format']
        })

        # transfer ownership to the new owner
        proxy.transfer_ownership(obj_id, self._node.keystore, owner)

        # set the output data object ids in the status
        output = status.get('output', default=[])
        output.append({
            'name': obj_name,
            'obj_id': obj_id
        })
        status.update('output', output)

