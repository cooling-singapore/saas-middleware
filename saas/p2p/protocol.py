import logging

from saas.cryptography.messenger import MessengerInvalidUseException, SecureMessenger

logger = logging.getLogger('p2p.protocol')


class P2PProtocol:
    """
    P2PProtocol is the base class for all P2P protocol classes. It provides convenience methods that is
    needed regardless of the specific protocol implementation.
    """
    def __init__(self, node, protocol_name, function_mapping):
        self._node = node
        self._protocol_name = protocol_name
        self._function_mapping = function_mapping

    def name(self):
        return self._protocol_name

    def supports(self, message_type):
        return message_type in self._function_mapping

    def handle_message(self, message, messenger):
        """
        Handles a message that has been received by forwarding it to the appropriate handler function for this
        type of message.
        :param message: the message
        :param messenger: the messenger that facilitates communication between the db and the peer
        :return: None
        """

        # check if that message is meant for this protocol
        if not message['protocol'] == self._protocol_name:
            raise MessengerInvalidUseException(
                f"message routed to the wrong protocol: protocol_name='{self._protocol_name}' message='{message}'")

        # check if we have a mapping for that message type
        if message['type'] not in self._function_mapping:
            raise MessengerInvalidUseException(
                f"message protocol '{self._protocol_name}' does not support message of this type: message='{message}'")

        # forward the message to the appropriate handler function
        self._function_mapping[message['type']](message['payload'], messenger)

    def prepare_message(self, message_type, payload=None):
        """
        Convenience method for preparing a message. It creates the body of the message and fills in the 'protocol',
        'type' and 'payload' fields.
        :param message_type: the message type
        :param payload: the (optional) payload, i.e., the type-specific content of this message
        :return: a dictionary containing 'protocol', 'type' and 'payload' fields
        """
        return {
            'protocol': self._protocol_name,
            'type': message_type,
            'payload': payload if payload else {}
        }

    def broadcast_message(self, message, exclude=None):
        """
        Broadcasts a message to all known peers (according to the db registry) unless they are excluded from the
        broadcast. Note that the db registry typically also includes a record for the db its hosted on. In order
        to prevent nodes sending messages to themselves as part of a broadcast, the sending db is added to the
        exclusion list by default.
        :param message: the message to be broadcast
        :param exclude: an (optional) list of peer iids which are to be excluded from the broadcast
        :return: None
        """
        logger.debug(f"broadcast message: {message}")

        # we always exclude ourselves
        if exclude is None:
            exclude = []
        exclude.append(self._node.id())

        # send message to all peers we know of
        for peer_iid, record in self._node.registry.get().items():
            # is this peer iid in the exclusion list?
            if peer_iid in exclude:
                continue

            # connect to the peer, send message and close connection
            peer, messenger = SecureMessenger.connect_to_peer(record['p2p_address'], self._node, peer_iid)
            messenger.send(message)
            messenger.close()
