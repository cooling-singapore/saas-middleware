"""
This module contains the code for the Data Object Repository P2P protocol.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import os
import logging

from saas.secure_messenger import SecureMessenger, MessengerProtocol

logger = logging.getLogger('DOR.Protocol')


class DataObjectRepositoryP2PProtocol(MessengerProtocol):
    id = "data_object_repository"

    def __init__(self, node):
        super().__init__(node, DataObjectRepositoryP2PProtocol.id, {
            'fetch': self.handle_fetch
        })

    def send_fetch(self, peer_address, obj_id, destination_path):
        logger.debug("send 'fetch' message to {}".format(peer_address))

        # connect to boot node
        peer, messenger = SecureMessenger.connect_to_peer(peer_address, self.node)
        logger.info("connected to peer (boot node) '{}'".format(peer.iid))

        # send 'fetch' message and receive the data object content from the peer
        response = messenger.request(self.prepare_message("fetch", {
            'object_id': obj_id
        }))

        if response == 'begin transfer':
            messenger.receive_attachment(destination_path)

        messenger.close()

    def handle_fetch(self, message, messenger):
        logger.debug("handle 'fetch' message")

        # get the object record for the data object
        obj_id = message['object_id']
        obj_record = self.node.dor.get(obj_id)
        if not obj_record:
            messenger.reply_error("no record found for {}".format(obj_id))

        # are we not the custodian?
        if not self.node.key.iid == obj_record['custodian_iid']:
            messenger.reply_error("not the custodian for {}".format(obj_id))

        else:
            # we should have the data object in our local DOR
            c_hash = obj_record['c_hash']
            obj_path = os.path.join(self.node.datastore_path, "{}.content".format(c_hash))
            if not os.path.exists(obj_path):
                messenger.reply_error("data object content {} of object {} expected but not found.".format(c_hash,
                                                                                                           obj_id))

            messenger.reply_ok("begin transfer")
            messenger.send_attachment(obj_path)

        messenger.close()
