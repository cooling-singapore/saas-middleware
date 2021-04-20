import logging

from saas.cryptography.messenger import MessengerProtocol

logger = logging.getLogger('NodeDB.Protocol')


class NodeDBP2PProtocol(MessengerProtocol):
    id = "node_db"

    def __init__(self, node):
        super().__init__(node, NodeDBP2PProtocol.id, {
            'update': self.handle_update
        })

    def broadcast(self, method, args):
        self.broadcast_message(self.prepare_message('update', {
            'method': method,
            'args': args
        }))

    def handle_update(self, message, messenger):
        self.node.db.handle_update(message)
