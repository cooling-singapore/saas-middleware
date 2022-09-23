from pydantic import BaseModel
from saascore.keystore.identity import Identity
from saascore.log import Logging

from saas.nodedb.exceptions import UnexpectedIdentityError
from saas.nodedb.schemas import NodeInfo, NodeDBSnapshot
from saas.p2p.exceptions import PeerUnavailableError
from saas.p2p.protocol import P2PProtocol, P2PMessage

logger = Logging.get('nodedb.protocol')


class UpdatePayload(BaseModel):
    origin_who: Identity
    origin_node: NodeInfo
    snapshot: NodeDBSnapshot
    reciprocate: bool


class LeavePayload(BaseModel):
    who: Identity


class NodeDBP2PProtocol(P2PProtocol):
    id = "node_db"

    def __init__(self, node) -> None:
        super().__init__(node, NodeDBP2PProtocol.id, {
            'update': (self._handle_update, UpdatePayload),
            'leave': (self._handle_leave, LeavePayload)
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
            try:
                response, peer = self.request(peer_address, self.prepare_message('update', UpdatePayload.parse_obj({
                    'origin_who': self.node.identity,
                    'origin_node': self.node.db.get_node(),
                    'snapshot': self.node.db.get_snapshot(exclude=[self.node.identity.id]),
                    'reciprocate': True,
                    # 'forward': False
                })))

                self._handle_update(UpdatePayload.parse_obj(response.content), peer)

            except PeerUnavailableError:
                logger.debug(f"Peer at {peer_address} unavailable -> Removing from NodeDB.")
                self.node.db.remove_node_by_address(peer_address)

            # get all nodes in the network and add any nodes that we may not have been aware of
            for node in self.node.db.get_network():
                if node.p2p_address not in processed and node.p2p_address not in remaining and \
                        node.p2p_address != self.node.p2p.address():
                    remaining.append(node.p2p_address)

    def perform_leave(self) -> None:
        message = self.prepare_message('leave', LeavePayload(who=self.node.identity))
        self.broadcast(message)
        self.node.db.reset_network()

    def _handle_update(self, payload: UpdatePayload, peer: Identity) -> P2PMessage:
        # does the identity check out?
        if payload.origin_who.id != peer.id:
            raise UnexpectedIdentityError({
                'expected': peer.dict(),
                'actual': payload.origin_who.dict()
            })

        # update the db information about the originator
        self.node.db.update_identity(payload.origin_who)
        self.node.db.update_network(payload.origin_node)

        # process the snapshot identities (if any)
        if payload.snapshot.update_identity:
            for identity in payload.snapshot.update_identity:
                self.node.db.update_identity(identity)

        # process the snapshot nodes (if any)
        if payload.snapshot.update_network:
            for node in payload.snapshot.update_network:
                self.node.db.update_network(node)

        # reciprocate with an update message (if requested)
        return self.prepare_message('update', UpdatePayload.parse_obj({
            'origin_who': self.node.identity,
            'origin_node': self.node.db.get_node(),
            'snapshot': self.node.db.get_snapshot(exclude=[self.node.identity.id, peer.id]),
            'reciprocate': False
        })) if payload.reciprocate else self.prepare_message('update_ack')

    def _handle_leave(self, payload: LeavePayload, peer: Identity) -> P2PMessage:
        # does the identity check out?
        if payload.who.id != peer.id:
            raise UnexpectedIdentityError({
                'expected': peer.dict(),
                'actual': payload.who.dict()
            })

        # update the db information about the peer
        self.node.db.update_identity(payload.who)
        self.node.db.remove_node_by_id(payload.who)

        return self.prepare_message('leave_ack')

    def broadcast_identity_update(self, identity: Identity) -> None:
        # this is a simple update. we expect the peer to NOT reciprocate and to NOT forward our message (because we are
        # broadcasting to everyone we know)
        self.broadcast(self.prepare_message('update', UpdatePayload.parse_obj({
            'origin_who': self.node.identity,
            'origin_node': self.node.db.get_node(),
            'snapshot': NodeDBSnapshot(update_identity=[identity]),
            'reciprocate': False
        })))
