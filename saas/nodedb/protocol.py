import logging

from saas.p2p.protocol import P2PProtocol


logger = logging.getLogger('nodedb.protocol')


class NodeDBP2PProtocol(P2PProtocol):
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
