import os

from saas.dor.exceptions import FetchDataObjectFailedError
from saas.keystore.identity import Identity
from saas.logging import Logging
from saas.p2p.exceptions import AttachmentNotFoundError
from saas.p2p.protocol import P2PProtocol, P2PMessage
from saas.helpers import write_json_to_file

logger = Logging.get('dor.protocol')


class DataObjectRepositoryP2PProtocol(P2PProtocol):
    id = "data_object_repository"

    def __init__(self, node) -> None:
        super().__init__(node, DataObjectRepositoryP2PProtocol.id, {
            'lookup': self._handle_lookup,
            'fetch': self._handle_fetch
        })

    def lookup(self, peer_address: (str, int), obj_ids: list[str], user: Identity = None) -> dict:
        result, _ = self.request(peer_address, self.prepare_message("lookup", {
            'obj_ids': obj_ids,
            'user_iid': user.id if user else None
        }))
        return result

    def _handle_lookup(self, message: dict) -> P2PMessage:
        # get the records for all the objects
        records = {}
        for obj_id in message['obj_ids']:
            # do we have a record for this data object?
            record = self.node.db.get_object_by_id(obj_id)
            if record is not None:
                records[obj_id] = record

        # if we have a user id, then we need to check if this user has access to the objects
        if message['user_iid'] is not None and len(records) > 0:
            # do we have an identity for the user?
            user = self.node.db.get_identity(message['user_iid'])
            if user is None:
                return self.prepare_message('lookup_response', {
                    'successful': False,
                    'reason': 'identity of user not found',
                    'user_iid': message['user_iid']
                })

            # check for every object
            for obj_id, record in records.items():
                record['user_has_permission'] = self.node.db.has_access(obj_id, user)

        return self.prepare_message('lookup_response', records)

    def fetch(self, peer_address: (str, int), obj_id: str,
              destination_meta_path: str, destination_content_path: str,
              user_iid: str = None, user_signature: str = None) -> None:

        response, attachment_path = self.request(peer_address, self.prepare_message("fetch", {
            'obj_id': obj_id,
            'user_iid': user_iid,
            'user_signature': user_signature
        }))

        # was the fetch attempt successful?
        if not response['successful']:
            raise FetchDataObjectFailedError({
                'peer_address': peer_address,
                'obj_id': obj_id,
                'user_iid': user_iid,
                'user_signature': user_signature,
                'response': response
            })

        # have we received an attachment?
        if not attachment_path or not os.path.isfile(attachment_path):
            raise AttachmentNotFoundError({
                'peer_address': peer_address,
                'obj_id': obj_id,
                'user_iid': user_iid,
                'user_signature': user_signature,
                'response': response
            })

        # write the data object descriptor to the destination path
        write_json_to_file(response['meta'], destination_meta_path)

        # move the data object content to the destination path
        os.rename(attachment_path, destination_content_path)

    def _handle_fetch(self, message: dict, peer: Identity) -> P2PMessage:
        # check if we have that data object
        obj_id = message['obj_id']
        obj_record = self.node.db.get_object_by_id(obj_id)
        if not obj_record:
            return self.prepare_message('fetch_data_object_response', {
                'successful': False,
                'reason': 'object not found',
                'object_id': obj_id
            })

        # check if the data object access is restricted and (if so) if the user has the required permission
        if obj_record['access_restricted']:
            # get the identity of the user
            user = self.node.db.get_identity(message['user_iid'])
            if user is None:
                return self.prepare_message('fetch_data_object_response', {
                    'successful': False,
                    'reason': 'identity of user not found',
                    'user_iid': message['user_iid']
                })

            # check if the user has permission to access this data object
            has_access = self.node.db.has_access(obj_id, user)
            if not has_access:
                return self.prepare_message('fetch_data_object_response', {
                    'successful': False,
                    'reason': 'user does not have access',
                    'user_iid': message['user_iid'],
                    'object_id': obj_id
                })

            # verify the access request
            token = f"{peer.id}:{obj_id}".encode('utf-8')
            if not user.verify(token, message['user_signature']):
                return self.prepare_message('fetch_data_object_response', {
                    'successful': False,
                    'reason': 'authorisation failed',
                    'user_iid': message['user_iid'],
                    'object_id': obj_id,
                    'token': token.decode('utf-8'),
                    'signature': message['user_signature']
                })

        # we should have the data object content in our local DOR
        content_path = self.node.dor.obj_content_path(obj_record['c_hash'])
        if not os.path.isfile(content_path):
            return self.prepare_message('fetch_data_object_response', {
                'successful': False,
                'reason': 'data object content not found',
                'user_iid': message['user_iid'],
                'object_id': obj_id,
                'c_hash': obj_record['c_hash']
            })

        # if all is good, send a reply with the meta information followed by the data object content as attachment
        record = self.node.db.get_object_by_id(obj_id)
        return self.prepare_message('fetch_data_object_response', {
            'successful': True,
            'meta': record
        }, content_path)
