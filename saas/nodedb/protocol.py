import logging

from saas.p2p.protocol import P2PProtocol


logger = logging.getLogger('nodedb.protocol')


class NodeDBP2PProtocol(P2PProtocol):
    id = "node_db"

    def __init__(self, node):
        super().__init__(node, NodeDBP2PProtocol.id, {
            'update': self.handle_update,
            'snapshot': self.handle_snapshot
        })

    def broadcast_update(self, method, args):
        self.broadcast_message(self.prepare_message('update', {
            'method': method,
            'args': args
        }))

    def send_snapshot(self, remote_address, snapshot):
        self.send_message(remote_address, self.prepare_message('snapshot', snapshot))

    def handle_update(self, message, messenger):
        self.node.db.handle_update(message)

    def handle_snapshot(self, message, messenger):
        self.node.db.handle_snapshot(message)
