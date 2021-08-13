import os
import logging
import json

from saas.cryptography.messenger import SecureMessenger
from saas.p2p.protocol import P2PProtocol
from saas.helpers import write_json_to_file

logger = logging.getLogger('dor.protocol')


class DataObjectRepositoryP2PProtocol(P2PProtocol):
    id = "data_object_repository"

    def __init__(self, node):
        super().__init__(node, DataObjectRepositoryP2PProtocol.id, {
            'lookup': self.handle_lookup,
            'fetch': self.handle_fetch,
        })

    def send_lookup(self, peer_address, object_ids, user):
        """
        Check with a given peer if it has data objects and if the user has access to them.
        :param peer_address: the address of the peer
        :param object_ids: a list of object ids
        :param user: the identity of the user
        :return:
        """
        peer, messenger = SecureMessenger.connect_to_peer(peer_address, self.node)
        if peer and messenger:
            reply = messenger.request(self.prepare_message('lookup', {
                'object_ids': object_ids,
                'user_iid': user.id()
            }))
            messenger.close()
            return reply

        else:
            return {}

    def handle_lookup(self, message, messenger):
        """
        Handles the lookup request: checks if the node has the data objects and if the given user has access.
        :param message:
        :param messenger:
        :return:
        """
        user = self.node.db.get_identity(iid=message['user_iid'])
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

        messenger.reply_ok(result)
        messenger.close()

    def send_fetch(self, peer_address, obj_id, destination_descriptor_path, destination_content_path,
                   user_iid=None, user_signature=None):
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

        peer, messenger = SecureMessenger.connect_to_peer(peer_address, self.node)
        if peer and messenger:
            reply = messenger.request(self.prepare_message("fetch", {
                'object_id': obj_id,
                'user_iid': user_iid,
                'user_signature': user_signature
            }))

            if reply['code'] == 200:
                write_json_to_file(reply['descriptor'], destination_descriptor_path)
                messenger.receive_attachment(destination_content_path)

            else:
                logger.info(f"fetching of data object failed (code={reply['code']}). reason: {reply['reason']}")

            messenger.close()
            return reply

        else:
            logger.info(f"fetching of data object failed. reason: peer ({peer_address}) cannot be reached.")
            return {
                'code': 503,
                'reason': f"peer ({peer_address}) cannot be reached."
            }

    def handle_fetch(self, message, messenger):
        """
        Handles a fetch request by performing a number of checks (data object available? access permission exists?
        access permission valid?). If successful, returns the c_hash and descriptor of the data object, followed by
        the data object content as a attachment.
        :param message:
        :param messenger:
        :return:
        """
        # check if we have that data object
        obj_id = message['object_id']
        obj_record = self.node.db.get_object_by_id(obj_id)
        if not obj_record:
            messenger.reply_ok({'code': 404, 'reason': f"data object (id={obj_id}) not found."})
            messenger.close()
            return

        # check if the data object access is restricted and (if so) if the user has the required permission
        if obj_record.access_restricted:
            # get the identity of the user
            user = self.node.db.get_identity(iid=message['user_iid'])
            if user is None:
                messenger.reply_ok({'code': 404, 'reason': f"identity of user (iid={message['user_iid']}) not found."})
                messenger.close()
                return

            # check if the user has permission to access this data object
            has_access = self.node.db.has_access(obj_id, user)
            if not has_access:
                messenger.reply_ok({'code': 403, 'reason': f"user (iid={message['user_iid']}) does not have access "
                                                           f"to data object (id={obj_id})."})
                messenger.close()
                return

            # verify the access request
            token = f"{messenger.peer.id()}:{obj_id}".encode('utf-8')
            if not user.signing_public_key().verify(token, message['user_signature']):
                messenger.reply_ok({'code': 403, 'reason': f"access authorisation failed "
                                                           f"(user_iid={user.id()}, obj_id={obj_id})."})
                messenger.close()
                return

        # we send the descriptor in the reply and stream the contents of the data object
        descriptor_path = self.node.dor.obj_descriptor_path(obj_id)
        if not os.path.isfile(descriptor_path):
            messenger.reply_ok({'code': 404, 'reason': f"descriptor for data object (obj_id={obj_id}) not found."})
            messenger.close()
            return

        # load the descriptor
        with open(descriptor_path) as f:
            descriptor = json.load(f)

        # we should have the data object content in our local DOR
        content_path = self.node.dor.obj_content_path(obj_record.c_hash)
        if not os.path.isfile(content_path):
            messenger.reply_ok({'code': 404, 'reason': f"content (c_hash={obj_record.c_hash}) for "
                                                       f"data object (obj_id={obj_id}) not found."})
            messenger.close()
            return

        # if all is good, send a reply followed by the data object content as attachment
        messenger.reply_ok({
            'code': 200,
            'descriptor': descriptor,
            'record': {
                'obj_id': obj_record.obj_id,
                'c_hash': obj_record.c_hash,
                'd_hash': obj_record.d_hash,
                'owner_iid': obj_record.owner_iid,
                'access_restricted': obj_record.access_restricted,
                'content_encrypted': obj_record.content_encrypted
            }
        })
        messenger.send_attachment(content_path)
        messenger.close()


