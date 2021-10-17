from typing import Optional

from saas.helpers import get_timestamp_now
from saas.keystore.identity import Identity
from saas.logging import Logging
from saas.nodedb.exceptions import UnexpectedIdentityError
from saas.p2p.protocol import P2PProtocol

logger = Logging.get('nodedb.protocol')


class NodeDBP2PProtocol(P2PProtocol):
    id = "node_db"

    def __init__(self, node) -> None:
        super().__init__(node, NodeDBP2PProtocol.id, {
            'update': self._handle_update,
            'leave': self._handle_leave
        })

    def _prepare_update_message(self, snapshot: dict, reciprocate: bool, forward: bool,
                                ignore: list[str] = None) -> dict:
        return self.prepare_message('update', {
            'self': {
                'identity': self.node.identity().serialise(),
                'network': {
                    'node_iid': self.node.identity().id,
                    'dor_service': self.node.dor is not None,
                    'rti_service': self.node.rti is not None,
                    'p2p_address': self.node.p2p.address(),
                    'rest_address': self.node.rest.address() if self.node.rest else None
                }
            },
            'snapshot': snapshot,
            'reciprocate': reciprocate,
            'forward': forward,
            'forward_ignore': [self.node.identity().id, *ignore] if ignore else [self.node.identity().id]
        })

    def perform_join(self, boot_node_address: (str, int)) -> None:
        # send an update to the boot node, then proceed to send updates to all peers that discovered along the way
        remaining = [boot_node_address]
        processed = []
        while len(remaining) > 0:
            peer_address = remaining.pop(0)
            processed.append(peer_address)

            # for join, we expect the peer to reciprocate and not to forward our message (because we will
            # contact them directly)
            self.update_peer(peer_address, reciprocate=True, forward=False)

            # get all nodes in the network and add any nodes that we may not have been aware of
            network = self.node.db.get_network_all()
            for record in network:
                if record['p2p_address'] not in processed and record['p2p_address'] not in remaining:
                    remaining.append(record['p2p_address'])

    def update_peer(self, peer_address: (str, int), reciprocate: bool, forward: bool) -> Optional[dict]:
        # send the message via request to the peer
        snapshot = self.node.db.create_sync_snapshot(exclude_self=True)
        message = self._prepare_update_message(snapshot, reciprocate=reciprocate, forward=forward)
        response, _ = self.request(peer_address, message)

        if reciprocate:
            self._handle_update(response, Identity.deserialise(response['self']['identity']))

        return response

    def broadcast_update(self, method: str, args: dict) -> None:
        # for a simple update, we except the peer to NOT reciprocate and to NOT forward our message (because we are
        # broadcasting to everyone we know)
        snapshot = {
            method: [args]
        }
        message = self._prepare_update_message(snapshot, reciprocate=False, forward=False)
        self.broadcast(message)

    def _handle_update(self, message: dict, peer: Identity) -> dict:
        # does the identity check out?
        if message['self']['identity']['iid'] != peer.id:
            raise UnexpectedIdentityError({
                'expected': peer,
                'message': message
            })

        # update the db information about the peer
        self.node.db.update_identity(message['self']['identity'])
        self.node.db.update_network(
            node_iid=message['self']['network']['node_iid'],
            last_seen=get_timestamp_now(),
            dor_service=message['self']['network']['dor_service'],
            rti_service=message['self']['network']['rti_service'],
            p2p_address=message['self']['network']['p2p_address'],
            rest_address=message['self']['network']['rest_address']
        )

        # process the snapshot
        for method_name in message['snapshot']:
            method = getattr(self.node.db, method_name)
            for args in message['snapshot'][method_name]:
                method(**args)

        # are we supposed to forward the message?
        if message['forward']:
            # add ourselves to the forward_ignore list and disable reciprocity (we don't do that when forwarding)
            message['forward_ignore'].append(self.node.identity().id)
            message['reciprocate'] = False

            # forward the message to all peers we know of (while skipping the ones in the ignore list)
            for record in self.node.db.get_network_all():
                if record['iid'] not in message['forward_ignore']:
                    self.request(record['p2p_address'], message)

        # reciprocate with an update message
        return self._prepare_update_message(self.node.db.create_sync_snapshot(exclude_self=True),
                                            reciprocate=False, forward=False) if message['reciprocate'] else None

    def broadcast_leave(self) -> None:
        message = self.prepare_message('leave', {
            'self': {
                'identity': self.node.identity().serialise(),
            }
        })

        result = self.broadcast(message)
        for unavailable in result['unavailable']:
            logger.debug(f"unavailable peer at {unavailable['p2p_address']} known to us as {unavailable['iid']} -> "
                         f"remove network record")
            self.node.db.remove_network(unavailable['iid'])

    def _handle_leave(self, message: dict, peer: Identity) -> None:
        # does the identity check out?
        if message['self']['identity']['iid'] != peer.id:
            raise UnexpectedIdentityError({
                'expected': peer,
                'message': message
            })

        # update the db information about the peer
        self.node.db.update_identity(message['self']['identity'])
        self.node.db.remove_network(peer.id)
