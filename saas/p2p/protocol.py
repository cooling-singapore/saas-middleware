from __future__ import annotations

from typing import Optional, Dict, List

from pydantic import BaseModel
from saascore.log import Logging

from saascore.keystore.identity import Identity

from saas.nodedb.schemas import NodeInfo
from saas.p2p.exceptions import PeerUnavailableError
from saas.p2p.messenger import SecureMessenger, P2PMessage

logger = Logging.get('p2p.protocol')


class BroadcastResponse(BaseModel):
    responses: Dict[str, P2PMessage]
    unavailable: List[NodeInfo]


class P2PProtocol:
    """
    P2PProtocol is the base class for all P2P protocol classes. It provides convenience methods that are
    needed regardless of the specific protocol implementation.
    """
    def __init__(self, node, protocol_name: str, function_mapping: dict):
        self._node = node
        self._protocol_name = protocol_name
        self._function_mapping = function_mapping
        self._seq_id_counter = 0

    def _next_seq_id(self) -> int:
        self._seq_id_counter += 1
        return self._seq_id_counter

    @property
    def node(self):
        return self._node

    @property
    def name(self) -> str:
        return self._protocol_name

    def supports(self, message_type: str) -> bool:
        return message_type in self._function_mapping

    def handle_message(self, message: P2PMessage, peer: Identity) -> Optional[P2PMessage]:
        """
        Handles a message that has been received by forwarding it to the appropriate handler function for this
        type of message.
        :param message: the message from the peer
        :param peer: the identity of the peer that sent the message
        :return: the response to be sent back to the peer (if any - None if not)
        """
        f, t = self._function_mapping[message.type]
        return f(t.parse_obj(message.content), peer)

    def prepare_message(self, message_type: str, content: BaseModel = None, attachment: str = None,
                        sequence_id: int = None) -> P2PMessage:
        """
        Convenience method for preparing a message. It creates the body of the message and fills in the 'protocol',
        'type' and 'payload' fields.
        :param message_type: the message type
        :param content: the (optional) type-specific content of the message
        :param attachment: the (optional) path to an attachment for the message
        :param sequence_id: an (optional) sequence id in order to create a logical link between request/response
        messages
        :return: a valid P2P protocol message
        """
        return P2PMessage(protocol=self._protocol_name, type=message_type, content=content.dict() if content else None,
                          attachment=attachment, sequence_id=sequence_id)

    def request(self, address: (str, int), request: P2PMessage) -> (P2PMessage, Identity):
        """
        Connects to a peer address, sends a request message and waits for a response message.
        :param address: the address (host:port) of the peer
        :param request: the request message
        :return: the response message
        """
        request.sequence_id = self._next_seq_id()

        peer, messenger = SecureMessenger.connect(address, self._node.identity, self._node.datastore)
        logger.debug(f"[req:{request.sequence_id:06d}] ({self._node.identity.id[:8]}) -> ({peer.id[:8]}) "
                     f"{request.protocol} {request.type} {request.attachment is not None}")

        response = messenger.send_request(request)
        logger.debug(f"[res:{request.sequence_id:06d}] ({self._node.identity.id[:8]}) <- ({peer.id[:8]})")

        messenger.close()
        return response, peer

    def broadcast(self, message: P2PMessage, exclude: list[str] = None) -> Optional[BroadcastResponse]:
        """
        Broadcasts a message to all known peers (according to the db registry) unless they are excluded from the
        broadcast. Note that the db registry typically also includes a record for the db its hosted on. In order
        to prevent nodes sending messages to themselves as part of a broadcast, the sending db is added to the
        exclusion list by default. If a peer cannot be reached, it is ignored.
        :param message: the message to be broadcast
        :param exclude: an (optional) list of peer iids which are to be excluded from the broadcast
        :return: all responses from peers that could be connected in form of a dict[peer_id, response]
        """
        message.sequence_id = self._next_seq_id()

        # we always exclude ourselves
        exclude = exclude if exclude else []
        exclude.append(self._node.identity.id)

        # send requests to all peers we know of and collect the responses
        responses = {}
        unavailable = []
        for node in self._node.db.get_network():
            # is this peer iid in the exclusion list?
            if node.identity.id in exclude:
                continue

            # connect to the peer (if it is online), send a request and keep the response. if a peer is not available,
            # we just skip it (as this is a broadcast we can't expect every peer in the list to be online/reachable).
            try:
                peer, messenger = SecureMessenger.connect(node.p2p_address, self._node.identity, self._node.datastore)
                responses[peer.id] = messenger.send_request(message)
                messenger.close()

            except PeerUnavailableError:
                unavailable.append(node)

        return BroadcastResponse.parse_obj({
            'responses': responses,
            'unavailable': unavailable
        })
