import logging

from saas.p2p.protocol import P2PProtocol


logger = logging.getLogger('nodedb.protocol')


class NodeDBP2PProtocol(P2PProtocol):
    id = "node_db"

    def __init__(self, node):
        super().__init__(node, NodeDBP2PProtocol.id, {
            'join': self.handle_join,
            'leave': self.handle_leave,

            'update': self.handle_update,
            'snapshot': self.handle_snapshot,
        })

    def send_join(self, peer_address):
        # first round: send 'join' to all known nodes in the network and receive snapshots from them. discover
        # nodes along the way.
        remaining = [f"{peer_address[0]}:{peer_address[1]}"]
        processed = []
        while len(remaining) > 0:
            address = remaining.pop(0)
            processed.append(address)

            # send the join message to solicit a snapshot
            response = self.send_request(peer_address, self.prepare_message('join'))

            # handle the snapshot
            message = response['payload']
            self.handle_snapshot(message)

            # get all nodes in the network and add any nodes that we may not have been aware of
            network = self.node.db.get_network()
            for record in network:
                if record.p2p_address not in processed and record.p2p_address not in remaining:
                    remaining.append(record.p2p_address)

        # by now we should have absorbed snapshots from all nodes in the network, let's update the other nodes
        # with a complete snapshot
        for address in processed:
            self.send_snapshot(address.split(":"))

    def handle_join(self, message, messenger):
        # when receiving a join message, reply by sending a snapshot
        snapshot = self.node.db.create_sync_snapshot()
        messenger.reply_ok(self.prepare_message('snapshot', snapshot))

    def broadcast_leave(self):
        self.broadcast_message(self.prepare_message("leave"))

    def handle_leave(self, message, messenger):
        self.node.db.remove_network_node(messenger.peer.id())

    def broadcast_update(self, method, args):
        self.broadcast_message(self.prepare_message('update', {
            'method': method,
            'args': args
        }))

    def handle_update(self, message, messenger=None):
        method = getattr(self.node.db, message['method'])
        method(**message['args'])

    def send_snapshot(self, peer_address):
        snapshot = self.node.db.create_sync_snapshot()
        self.send_message(peer_address, self.prepare_message('snapshot', snapshot))

    def handle_snapshot(self, message, messenger=None):
        for method_name in message:
            method = getattr(self.node.db, method_name)
            for args in message[method_name]:
                method(**args)
