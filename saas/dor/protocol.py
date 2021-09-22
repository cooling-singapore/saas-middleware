import os
import logging
import subprocess
from typing import Optional

from saas.keystore.identity import Identity
from saas.p2p.protocol import P2PProtocol
from saas.helpers import write_json_to_file, read_json_from_file

logger = logging.getLogger('dor.protocol')


class DataObjectRepositoryP2PProtocol(P2PProtocol):
    id = "data_object_repository"

    def __init__(self, node):
        super().__init__(node, DataObjectRepositoryP2PProtocol.id, {
            'lookup': self._handle_lookup,
            'fetch': self._handle_fetch,
        })

    def send_lookup(self, peer_address: (str, int), object_ids: dict, user: Identity) -> dict:
        """
        Check with a given peer if it has data objects and if the user has access to them.
        :param peer_address: the address of the peer
        :param object_ids: a list of object ids
        :param user: the identity of the user
        :return:
        """

        try:
            response, _ = self.request(peer_address, self.prepare_message('lookup', {
                'object_ids': object_ids,
                'user_iid': user.id
            }))
            return response

        except ConnectionRefusedError:
            return {}

    def _handle_lookup(self, message: dict, peer: Identity) -> dict:
        """
        Handles the lookup request: checks if the node has the data objects and if the given user has access.
        :param message:
        :param messenger:
        :return:
        """
        user = self.node.db.get_identity(iid=message['user_iid'])
        if user is None:
            return self.prepare_message('lookup_response', {
                'successful': False,
                'reason': 'identity of user not found',
                'user_iid': message['user_iid']
            })

        result = {}
        for obj_id in message['object_ids']:
            record = self.node.db.get_object_by_id(obj_id)
            if record is not None:
                result[obj_id] = {
                    'custodian_address': self.node.p2p.address(),
                    'access_restricted': record.access_restricted,
                    'content_encrypted': record.content_encrypted,
                    'user_has_permission': self.node.db.has_access(obj_id, user) if user else False
                }

        return self.prepare_message('lookup_response', {
            'successful': True,
            'result': result
        })

    def send_fetch(self, peer_address: (str, int), obj_id: str,
                   destination_descriptor_path: str, destination_content_path: str,
                   user_iid: str = None, user_signature: str = None) -> Optional[dict]:
        """
        Attempts to fetch a data object from a peer. If successful, the data object descriptor and content is
        stored at the specified locations.
        :param peer_address:
        :param obj_id:
        :param destination_descriptor_path:
        :param destination_content_path:
        :param user_iid:
        :param user_signature:
        :return: the 'c_hash' of the data object if successful or None otherwise.
        """

        try:
            response, attachment_path = self.request(peer_address, self.prepare_message("fetch", {
                'object_id': obj_id,
                'user_iid': user_iid,
                'user_signature': user_signature
            }))

            if response['successful']:
                if not attachment_path or not os.path.isfile(attachment_path):
                    raise RuntimeError(f"attachment excpected but not found")

                write_json_to_file(response['descriptor'], destination_descriptor_path)
                result = subprocess.run(['mv', attachment_path, destination_content_path], capture_output=True)
                if result.returncode != 0:
                    raise RuntimeError(f"could not move attachment "
                                       f"from {attachment_path} "
                                       f"to {destination_content_path}")

                response['code'] = 200
                return response

        except ConnectionRefusedError:
            return None

        logger.info(f"fetching of data object failed. reason: {response['reason']}")
        response['code'] = -1
        return response

    def _handle_fetch(self, message: dict, peer: Identity) -> dict:
        # check if we have that data object
        obj_id = message['object_id']
        obj_record = self.node.db.get_object_by_id(obj_id)
        if not obj_record:
            return self.prepare_message('fetch_response', {
                'successful': False,
                'reason': 'object not found',
                'object_id': obj_id
            })

        # check if the data object access is restricted and (if so) if the user has the required permission
        if obj_record.access_restricted:
            # get the identity of the user
            user = self.node.db.get_identity(iid=message['user_iid'])
            if user is None:
                return self.prepare_message('fetch_response', {
                    'successful': False,
                    'reason': 'identity of user not found',
                    'user_iid': message['user_iid']
                })

            # check if the user has permission to access this data object
            has_access = self.node.db.has_access(obj_id, user)
            if not has_access:
                return self.prepare_message('fetch_response', {
                    'successful': False,
                    'reason': 'user does not have access',
                    'user_iid': message['user_iid'],
                    'object_id': obj_id
                })

            # verify the access request
            token = f"{peer.id}:{obj_id}".encode('utf-8')
            if not user.verify(token, message['user_signature']):
                return self.prepare_message('fetch_response', {
                    'successful': False,
                    'reason': 'authorisation failed',
                    'user_iid': message['user_iid'],
                    'object_id': obj_id,
                    'token': token.decode('utf-8'),
                    'signature': message['user_signature']
                })

        # we should have the data object content in our local DOR
        content_path = self.node.dor.obj_content_path(obj_record.c_hash)
        if not os.path.isfile(content_path):
            return self.prepare_message('fetch_response', {
                'successful': False,
                'reason': 'data object content not found',
                'user_iid': message['user_iid'],
                'object_id': obj_id,
                'c_hash': obj_record.c_hash
            })

        # we send the descriptor in the reply and stream the contents of the data object
        descriptor_path = self.node.dor.obj_descriptor_path(obj_id)
        if not os.path.isfile(descriptor_path):
            return self.prepare_message('fetch_response', {
                'successful': False,
                'reason': 'data object descriptor not found',
                'user_iid': message['user_iid'],
                'object_id': obj_id
            })

        # if all is good, send a reply followed by the data object content as attachment
        descriptor = read_json_from_file(descriptor_path)
        return self.prepare_message('fetch_response', {
            'successful': True,
            'descriptor': descriptor,
            'record': {
                'obj_id': obj_record.obj_id,
                'c_hash': obj_record.c_hash,
                'd_hash': obj_record.d_hash,
                'owner_iid': obj_record.owner_iid,
                'access_restricted': obj_record.access_restricted,
                'content_encrypted': obj_record.content_encrypted
            }
        }, content_path)
