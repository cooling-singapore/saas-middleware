"""
This module contains the code for the Data Object Repository P2P protocol.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import os
import logging
import json

from saas.cryptography.messenger import MessengerRuntimeError, SecureMessenger
from saas.p2p.protocol import P2PProtocol
from saas.utilities.general_helpers import dump_json_to_file

logger = logging.getLogger('dor.protocol')


class DataObjectRepositoryP2PProtocol(P2PProtocol):
    id = "data_object_repository"

    def __init__(self, node):
        super().__init__(node, DataObjectRepositoryP2PProtocol.id, {
            'fetch': self.handle_fetch
        })

    def send_fetch(self, peer_address, obj_id):
        # connect to peer
        peer, messenger = SecureMessenger.connect_to_peer(peer_address, self.node)
        logger.info(f"connected to peer '{peer.iid}'")

        # send 'fetch' message and receive the data object descriptor and content from the peer
        try:
            reply = messenger.request(self.prepare_message("fetch", {
                'object_id': obj_id
            }))
            logger.debug(f"send_fetch: reply={reply}")
            c_hash = reply['c_hash']

            destination_descriptor_path = self.node.dor.obj_descriptor_path(obj_id, cache=True)
            dump_json_to_file(reply['descriptor'], destination_descriptor_path)

            destination_content_path = self.node.dor.obj_content_path(c_hash, cache=True)
            messenger.receive_attachment(destination_content_path)
            messenger.close()
            return reply['c_hash']

        except MessengerRuntimeError as e:
            if not e.status == 404:
                logger.error(f"runtime error during send_fetch: {e.status} {e.message}")

            messenger.close()
            return None

    def handle_fetch(self, message, messenger):
        # check if we have that data object
        obj_id = message['object_id']
        obj_record = self.node.db.get_object_by_id(obj_id)
        if not obj_record:
            messenger.reply_error(404, f"{obj_id} not found")
            messenger.close()
            return

        # if we have it, then we send the descriptor in the reply and stream the contents of the data object
        descriptor_path = self.node.dor.obj_descriptor_path(obj_id)
        if not os.path.isfile(descriptor_path):
            messenger.reply_error(500, f"descriptor expected but not found for data object {obj_id}")
            messenger.close()
            return

        # load the descriptor
        with open(descriptor_path) as f:
            descriptor = json.load(f)

        # we should have the data object content in our local DOR
        c_hash = obj_record.c_hash
        content_path = self.node.dor.obj_content_path(c_hash)
        if not os.path.isfile(content_path):
            messenger.reply_error(500, f"content {c_hash} expected but not found for data object {obj_id}.")
            messenger.close()
            return

        messenger.reply_ok({
            'c_hash': c_hash,
            'descriptor': descriptor
        })
        messenger.send_attachment(content_path)
        messenger.close()
