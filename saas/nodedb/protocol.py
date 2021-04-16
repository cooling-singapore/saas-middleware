"""
This module contains the code for the NodeDB P2P protocol.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging

from saas.cryptography.messenger import MessengerProtocol, SecureMessenger

logger = logging.getLogger('NodeDB.Protocol')


class NodeDBP2PProtocol(MessengerProtocol):
    id = "node_db"

    def __init__(self, node):
        super().__init__(node, NodeDBP2PProtocol.id, {
            'updates': self.handle_updates
            # 'request_snapshot': self.handle_request_snapshot,
            # 'snapshot': self.handle_snapshot
        })

    @classmethod
    def make_sql_insert_item(cls, table_name, parameters, or_ignore):
        return {
            'action': 'sql_insert',
            'table_name': table_name,
            'parameters': parameters,
            'or_ignore': or_ignore
        }

    @classmethod
    def make_sql_update_item(cls, table_name, update_parameters, where_parameters):
        return {
            'action': 'sql_update',
            'table_name': table_name,
            'update_parameters': update_parameters,
            'where_parameters': where_parameters
        }

    @classmethod
    def make_sql_delete_item(cls, table_name, where_parameters):
        return {
            'action': 'sql_delete',
            'table_name': table_name,
            'where_parameters': where_parameters
        }

    def broadcast_updates(self, items):
        self.broadcast_message(self.prepare_message("updates", {
            'items': items
        }))

    def handle_updates(self, message, messenger):
        self.node.db.handle_updates(message['items'])

    # def request_snapshot(self, peer_address):
    #     logger.debug("send 'request_snapshot' message to {}".format(peer_address))
    #
    #     # connect to boot node
    #     peer, messenger = SecureMessenger.connect_to_peer(peer_address, self.node)
    #     logger.info("connected to peer '{}'".format(peer.iid))
    #
    #     response = messenger.request(self.prepare_message("request_snapshot", {}))
    #     messenger.close()
    #
    # def handle_request_snapshot(self, message, messenger):
    #     snapshot = {}
    #     for table in self.node.db.tables:
    #         snapshot[table.name] = table.select()
    #
    #     messenger.reply_ok(self.prepare_message("snapshot", snapshot))
    #
    # def handle_snapshot(self, message, messenger):
    #     messenger.reply_error(501, "not implemented yet")
