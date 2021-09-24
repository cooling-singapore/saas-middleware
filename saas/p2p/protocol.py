from typing import Optional

from saas.keystore.identity import Identity
from saas.logging import Logging
from saas.p2p.exceptions import PeerUnavailableError
from saas.p2p.messenger import SecureMessenger

logger = Logging.get('p2p.protocol')


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

    def _next_seq_id(self) -> str:
        self._seq_id_counter += 1
        return f"{self._seq_id_counter:04d}"

    @property
    def node(self):
        return self._node

    @property
    def name(self) -> str:
        return self._protocol_name

    def supports(self, message_type: str) -> bool:
        return message_type in self._function_mapping

    def handle_message(self, message: dict, peer: Identity) -> Optional[dict]:
        """
        Handles a message that has been received by forwarding it to the appropriate handler function for this
        type of message.
        :param message: the message from the peer
        :param peer: the identity of the peer that sent the message
        :return: the response to be sent back to the peer (if any - None if not)
        """
        return self._function_mapping[message['type']](message['content'], peer)

    def prepare_message(self, message_type: str, content: dict = None, attachment: str = None) -> dict:
        """
        Convenience method for preparing a message. It creates the body of the message and fills in the 'protocol',
        'type' and 'payload' fields.
        :param message_type: the message type
        :param content: the (optional) type-specific content of the message
        :param attachment: the (optional) path to an attachment for the message
        :return: a valid P2P protocol message
        """
        return {
            'protocol': self._protocol_name,
            'type': message_type,
            'content': content if content else {},
            'attachment': attachment
        }

    def request(self, address: (str, int), message: dict) -> (dict, str):
        """
        Connects to a peer address, sends a request message and waits for a response message.
        :param address: the address (host:port) of the peer
        :param message: the request message
        :return: the response message
        """
        seq_id = self._next_seq_id()

        peer, messenger = SecureMessenger.connect(address, self._node.identity(), self._node.datastore())
        logger.debug(f"[req:{seq_id}] ({self._node.identity().short_id}) -> ({peer.short_id}) "
                     f"{message['protocol']} {message['type']} {message['attachment'] is not None}")

        response = messenger.send_request(message, message['attachment'])
        logger.debug(f"[res:{seq_id}] ({self._node.identity().short_id}) <- ({peer.short_id})")

        messenger.close()
        return response['content'], response['attachment']

    def broadcast(self, message: dict, exclude: list[str] = None) -> dict[str, dict]:
        """
        Broadcasts a message to all known peers (according to the db registry) unless they are excluded from the
        broadcast. Note that the db registry typically also includes a record for the db its hosted on. In order
        to prevent nodes sending messages to themselves as part of a broadcast, the sending db is added to the
        exclusion list by default. If a peer cannot be reached, it is ignored.
        :param message: the message to be broadcast
        :param exclude: an (optional) list of peer iids which are to be excluded from the broadcast
        :return: all responses from peers that could be connected in form of a dict[peer_id, response]
        """

        # we always exclude ourselves
        exclude = exclude if exclude else []
        exclude.append(self._node.identity().id)

        # send requests to all peers we know of and collect the responses
        responses = {}
        unavailable = []
        for record in self._node.db.get_network():
            # is this peer iid in the exclusion list?
            if record['iid'] in exclude:
                continue

            # connect to the peer (if it is online), send a request and keep the response. if a peer is not available,
            # we just skip it (this is a broadcast and we can't expect every peer in the list to be online/reachable).
            try:
                peer, messenger = SecureMessenger.connect(record['p2p_address'],
                                                          self._node.identity(),
                                                          self._node.datastore())
                responses[peer.id] = messenger.send_request(message, message['attachment'])
                messenger.close()

            except PeerUnavailableError:
                unavailable.append(['record.iid'])

        return {
            'responses': responses,
            'unavailable': unavailable
        }
