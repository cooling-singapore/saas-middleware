import logging

from saas.cryptography.messenger import MessengerInvalidUseException, SecureMessenger

logger = logging.getLogger('p2p.protocol')


class P2PProtocol:
    """
    P2PProtocol is the base class for all P2P protocol classes. It provides convenience methods that is
    needed regardless of the specific protocol implementation.
    """
    def __init__(self, node, protocol_name, function_mapping):
        self.node = node
        self.protocol_name = protocol_name
        self._function_mapping = function_mapping

    def name(self):
        return self.protocol_name

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
        if not message['protocol'] == self.protocol_name:
            raise MessengerInvalidUseException(
                f"message routed to the wrong protocol: protocol_name='{self.protocol_name}' message='{message}'")

        # check if we have a mapping for that message type
        if message['type'] not in self._function_mapping:
            raise MessengerInvalidUseException(
                f"message protocol '{self.protocol_name}' does not support message of this type: message='{message}'")

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
            'protocol': self.protocol_name,
            'type': message_type,
            'payload': payload if payload else {}
        }

    def send_message(self, remote_address, message):
        logger.debug(f"send message: {message}")

        # connect to the peer (if it can be reached), send message and close connection
        peer, messenger = SecureMessenger.connect_to_peer(remote_address, self.node)
        if messenger is not None:
            messenger.send(message)
            messenger.close()
            return True

        return False

    def send_request(self, remote_address, message):
        logger.debug(f"send request: {message}")

        # connect to the peer, send request and close connection
        peer, messenger = SecureMessenger.connect_to_peer(remote_address, self.node)
        response = messenger.request(message)
        logger.debug(f"received response: {response}")

        messenger.close()
        return response

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
        exclude.append(self.node.identity().id)

        # send message to all peers we know of
        for record in self.node.db.get_network():
            # is this peer iid in the exclusion list?
            if record.iid in exclude:
                continue

            # connect to the peer (if it is online), send message and close connection
            # if a peer is not available, we just skip it. this is a broadcast and we can't expect every peer
            # in the list to be online/reachable.
            _, messenger = SecureMessenger.connect_to_peer(record.p2p_address.split(":"), self.node, record.iid)
            if messenger:
                messenger.send(message)
                messenger.close()
