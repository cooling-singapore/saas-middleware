import logging

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.p2p.protocol import P2PProtocol
from saas.utilities.general_helpers import get_timestamp_now

logger = logging.getLogger('keystore.protocol')


class KeystoreP2PProtocol(P2PProtocol):
    id = "keystore"

    def __init__(self, node, keystore, max_session_start_distance=6*3600):
        super().__init__(node, KeystoreP2PProtocol.id, {
            'fetch-key': self.handle_fetch_key,
        })

        self._keystore = keystore
        self._max_session_start_distance = max_session_start_distance * 1000

    def request_key(self, peer_address, user_iid, session_public_key, session_start, user_signature, session_signature, obj_id):
        response = self.send_request(peer_address, self.prepare_message('fetch-key', {
            'user_iid': user_iid,
            'user_signature': user_signature,
            'session_start': session_start,
            'session_public_key': session_public_key,
            'session_signature': session_signature,
            'obj_id': obj_id
        }))

        return response['key']

    def handle_fetch_key(self, message, messenger):
        # check if we know the user
        user_iid = message['user_iid']
        user = self.node.db.get_public_key(user_iid)
        if user is None:
            messenger.reply_ok(self.prepare_message('fetch-key-response', {
                'key': None,
                'reason': f"unknown user with iid={user_iid}"
            }))
            messenger.close()
            return

        # check if the session key is valid
        session_public_key = message['session_public_key']
        session = RSAKeyPair.from_public_key_string(session_public_key)
        if session is None:
            messenger.reply_ok(self.prepare_message('fetch-key-response', {
                'key': None,
                'reason': "invalid session key"
            }))
            messenger.close()
            return

        # determine token
        session_start = message['session_start']
        token = f"{session.iid}{session_start}{user_iid}".encode('utf-8')

        # check if user signatures is valid
        user_signature = message['user_signature']
        if not user.verify(token, user_signature):
            messenger.reply_ok(self.prepare_message('fetch-key-response', {
                'key': None,
                'reason': f"invalid user signature for session token"
            }))
            messenger.close()
            return

        # check if session signatures is valid
        session_signature = message['session_signature']
        if not session.verify(token, session_signature):
            messenger.reply_ok(self.prepare_message('fetch-key-response', {
                'key': None,
                'reason': f"invalid session signature for session token"
            }))
            messenger.close()
            return

        # check if session start was too long ago
        if get_timestamp_now() > session_start + self._max_session_start_distance:
            messenger.reply_ok(self.prepare_message('fetch-key-response', {
                'key': None,
                'reason': 'maximum session start distance violation'
            }))
            messenger.close()
            return

        # check if the requesting user has an access permission

        # check if we have an access key for this object
        obj_id = message['obj_id']
        key = self._keystore.get_object_key(obj_id)
        if key is None:
            messenger.reply_ok(self.prepare_message('fetch-key-response', {
                'key': None,
                'reason': 'no key found'
            }))
            messenger.close()

        # encrypt key and return it
        encrypted_key = session.encrypt(key)
        messenger.reply_ok(self.prepare_message('fetch-key-response', {
            'key': encrypted_key,
            'reason': None
        }))
        messenger.close()




    # def send_join(self, peer_address):
    #     # first round: send 'join' to all known nodes in the network and receive snapshots from them. discover
    #     # nodes along the way.
    #     remaining = [f"{peer_address[0]}:{peer_address[1]}"]
    #     processed = []
    #     while len(remaining) > 0:
    #         address = remaining.pop(0)
    #         processed.append(address)
    #
    #         # send the join message to solicit a snapshot
    #         response = self.send_request(peer_address, self.prepare_message('join'))
    #
    #         # handle the snapshot
    #         message = response['payload']
    #         self.handle_snapshot(message)
    #
    #         # get all nodes in the network and add any nodes that we may not have been aware of
    #         network = self.node.db.get_network()
    #         for record in network:
    #             if record.p2p_address not in processed and record.p2p_address not in remaining:
    #                 remaining.append(record.p2p_address)
    #
    #     # by now we should have absorbed snapshots from all nodes in the network, let's update the other nodes
    #     # with a complete snapshot
    #     for address in processed:
    #         self.send_snapshot(address.split(":"))
    #
    # def handle_join(self, message, messenger):
    #     # when receiving a join message, reply by sending a snapshot
    #     snapshot = self.node.db.create_sync_snapshot()
    #     messenger.reply_ok(self.prepare_message('snapshot', snapshot))
    #
    # def broadcast_leave(self):
    #     self.broadcast_message(self.prepare_message("leave"))
    #
    # def handle_leave(self, message, messenger):
    #     self.node.db.remove_network_node(messenger.peer.iid)
    #
    # def broadcast_update(self, method, args):
    #     self.broadcast_message(self.prepare_message('update', {
    #         'method': method,
    #         'args': args
    #     }))
    #
    # def handle_update(self, message, messenger=None):
    #     method = getattr(self.node.db, message['method'])
    #     method(**message['args'])
    #
    # def send_snapshot(self, peer_address):
    #     snapshot = self.node.db.create_sync_snapshot()
    #     self.send_message(peer_address, self.prepare_message('snapshot', snapshot))
    #
    # def handle_snapshot(self, message, messenger=None):
    #     for method_name in message:
    #         method = getattr(self.node.db, method_name)
    #         for args in message[method_name]:
    #             method(**args)
    #
