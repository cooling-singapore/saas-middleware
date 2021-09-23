from saas.keystore.identity import Identity
from saas.logging import Logging
from saas.p2p.protocol import P2PProtocol

logger = Logging.get('nodedb.protocol')


class NodeDBP2PProtocol(P2PProtocol):
    id = "node_db"

    def __init__(self, node) -> None:
        super().__init__(node, NodeDBP2PProtocol.id, {
            'join': self._handle_join,
            'leave': self._handle_leave,
            'update': self._handle_update,
            'snapshot': self._handle_snapshot,
        })

    def send_join(self, peer_address: (str, int)) -> None:
        # first round: send 'join' to all known nodes in the network and receive snapshots from them. discover
        # nodes along the way.
        remaining = [peer_address]
        processed = []
        while len(remaining) > 0:
            address = remaining.pop(0)
            processed.append(address)

            # send the join message to solicit a snapshot
            response, _ = self.request(peer_address, self.prepare_message('join'))

            # handle the received snapshot
            self._handle_snapshot(response)

            # get all nodes in the network and add any nodes that we may not have been aware of
            network = self.node.db.get_network()
            for record in network:
                r_address = record['p2p_address']
                if r_address not in processed and r_address not in remaining:
                    remaining.append(r_address)

        # by now we should have absorbed snapshots from all nodes in the network, let's update the other nodes
        # with a complete snapshot
        for address in processed:
            self.send_snapshot(address)

    def broadcast_leave(self) -> None:
        self.broadcast(self.prepare_message("leave"))

    def broadcast_update(self, method, args) -> None:
        self.broadcast(self.prepare_message('update', {
            'method': method,
            'args': args
        }))

    def send_snapshot(self, peer_address: (str, int)) -> None:
        snapshot = self.node.db.create_sync_snapshot()
        self.request(peer_address, self.prepare_message('snapshot', snapshot))

    def _handle_join(self, message, peer: Identity) -> dict:
        snapshot = self.node.db.create_sync_snapshot()
        return self.prepare_message('snapshot', snapshot)

    def _handle_leave(self, message: dict, peer: Identity) -> None:
        self.node.db.remove_network_node(peer.id)

    def _handle_update(self, message: dict, peer: Identity) -> None:
        method = getattr(self.node.db, message['method'])
        method(**message['args'])

    def _handle_snapshot(self, message: dict, peer: Identity = None) -> None:
        for method_name in message:
            method = getattr(self.node.db, method_name)
            for args in message[method_name]:
                method(**args)
