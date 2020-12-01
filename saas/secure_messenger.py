"""
This module contains the code for the SecureMessenger including Exceptions and the MessengerProtocol base class
for custom P2P protocol implementations.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import os
import logging
import json
import base64
import socket

from saas.eckeypair import ECKeyPair

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

logger = logging.getLogger('SecureMessenger')


class MessengerException(Exception):
    """
    MessengerException is the base class for all messenger-related exception classes.
    """
    def __init__(self, info):
        super().__init__(info)


class MessengerRuntimeError(MessengerException):
    """
    MessengerRuntimeError indicates that there has been an error during runtime.
    """
    def __init__(self, info, message=None):
        super().__init__(info)
        self.message = message


class MessengerInvalidUseException(MessengerException):
    """
    MessengerInvalidUseException indicates that the messenger is used in an invalid way. This kind of error
    indicates that the cause of the problem may be due to a bug or programming error in the code. In other
    words this exception indicates that a situation has occurred that shouldn't be possible.
    """
    def __init__(self, info):
        super().__init__(info)


class MessengerProtocol:
    """
    MessengerProtocol is the base class for all P2P protocol classes. It provides convenience methods that is
    needed regardless of the specific protocol implementation.
    """
    def __init__(self, node, protocol_name, function_mapping):
        self.node = node
        self.protocol_name = protocol_name
        self.function_mapping = function_mapping

    def handle_message(self, message, messenger):
        """
        Handles a message that has been received by forwarding it to the appropriate handler function for this
        type of message.
        :param message: the message
        :param messenger: the messenger that facilitates communication between the node and the peer
        :return: None
        """

        # check if that message is meant for this protocol
        if not message['protocol'] == self.protocol_name:
            raise MessengerInvalidUseException(
                "message routed to the wrong protocol: protocol_name='{}' message='{}'".format(self.protocol_name,
                                                                                               message))

        # check if we have a mapping for that message type
        if message['type'] not in self.function_mapping:
            raise MessengerInvalidUseException(
                "message protocol '{}' does not support message of this type: message='{}'".format(self.protocol_name,
                                                                                                   message))

        # forward the message to the appropriate handler function
        self.function_mapping[message['type']](message['payload'], messenger)

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

    def broadcast_message(self, message, exclude=None):
        """
        Broadcasts a message to all known peers (according to the node registry) unless they are excluded from the
        broadcast. Note that the node registry typically also includes a record for the node its hosted on. In order
        to prevent nodes sending messages to themselves as part of a broadcast, the sending node is added to the
        exclusion list by default.
        :param message: the message to be broadcast
        :param exclude: an (optional) list of peer iids which are to be excluded from the broadcast
        :return: None
        """
        # we always exclude ourselves
        if exclude is None:
            exclude = []
        exclude.append(self.node.key.iid)

        # send message to all peers we know of
        for peer_iid, record in self.node.registry.get().items():
            # is this peer iid in the exclusion list?
            if peer_iid in exclude:
                continue

            # connect to the peer, send message and close connection
            peer, messenger = SecureMessenger.connect_to_peer(record['address'], self.node, peer_iid)
            messenger.send(message)
            messenger.close()


class SecureMessenger:
    """
    SecureMessenger is a wrapper for a TCP socket connection. It uses encryption to secure the communication between
    two nodes. For this purpose, a key exchange handshake is performed immediately upon establishing a connection.
    All message exchange henceforth is encrypted.
    """
    def __init__(self, peer_socket):
        self.peer_socket = peer_socket
        self.peer = None
        self.cipher = None

    @classmethod
    def connect_to_peer(cls, peer_address, self_node, expected_peer_iid=None):
        """
        Connect to a peer given its address.
        :param peer_address: the address of the peer
        :param self_node: the counterparty for the peer (i.e., the node that wants to connect to the peer)
        :param expected_peer_iid: the (optional) expected iid for the peer at the given address. If peer iid and
        expected iid do not match, a warning message is produced in the log.
        :return: the messenger that facilitates communication between the node and the peer
        """
        try:
            peer_socket = socket.create_connection(peer_address)
            messenger = SecureMessenger(peer_socket)
            peer = messenger.handshake(self_node)
            logger.info("connected to peer '{}'".format(peer.iid))

            # if we have an expected peer iid, do a comparison if it matches with what the peer is telling us
            if not expected_peer_iid == peer.iid:
                logger.warning("unexpected iid for peer at address {}: expected={} idd_as_per_peer={}".format(
                    peer_address, expected_peer_iid, peer.iid
                ))

            return peer, messenger

        except ConnectionRefusedError:
            logger.warning("cannot connect to peer at address '{}'".format(peer_address))
            return None, None

    @classmethod
    def accept_connection_by_peer(cls, node):
        """
        Accepts and incoming connection from a peer.
        :param node: the node whose socket server is used to accept the incoming connection
        :return: the messenger that facilitates communication between the node and the peer
        """
        client_socket, client_address = node.server_socket.accept()
        messenger = SecureMessenger(client_socket)
        peer = messenger.handshake(node)
        logger.info("connected by peer '{}'".format(peer.iid))

        return peer, messenger

    def handshake(self, node):
        """
        Performs the handshake (i.e., key exchange) in order to secure all further message exchange.
        :param node: the node that represents the counterparty to the handshake with the peer
        :return: the peer identity (i.e., a key pair with public key component only)
        """
        # generate an ephemeral key pair
        key = ECKeyPair.create_new()

        # send and receive peer public key information
        self.send_raw(key.public_as_bytes())
        peer_key = ECKeyPair.from_public_key_bytes(self.receive_raw())

        # generate the shared key
        shared_key = key.private_key.exchange(ec.ECDH(), peer_key.public_key)
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None
        ).derive(shared_key)

        # initialise the cipher used to encrypt/decrypt messages
        self.cipher = Fernet(base64.urlsafe_b64encode(session_key))

        # exchange public keys. note that this is not strictly speaking part of the handshake. it is merely for the
        # benefit of the peers to know who their counterparty is.
        self.send({'public_key': node.key.public_as_string()})
        self.peer = ECKeyPair.from_public_key_string(self.receive()['public_key'])

        return self.peer

    def close(self):
        """
        Closes the connection.
        :return: None
        """
        self.peer_socket.close()
        self.peer_socket = None
        self.peer = None
        self.cipher = None

    def receive_raw(self):
        """
        Receives a raw message (i.e., bytes[])
        :return: the raw message as byte array
        """
        chunks = []
        received = 0
        while received < 4:
            chunk = self.peer_socket.recv(min(4 - received, 4))
            if chunk == b'':
                raise MessengerRuntimeError("socket connection broken")

            chunks.append(chunk)
            received += len(chunk)

        msg_length_byte = b''.join(chunks)
        msg_length = int.from_bytes(msg_length_byte, 'big')

        chunks = []
        received = 0
        while received < msg_length:
            chunk = self.peer_socket.recv(min(msg_length - received, 2048))
            if chunk == b'':
                raise MessengerRuntimeError("socket connection broken")

            chunks.append(chunk)
            received += len(chunk)

        message = b''.join(chunks)
        return message

    def send_raw(self, message):
        """
        Sends a raw message (i.e., bytes[])
        :param message: the message as byte array
        :return: total bytes sent
        """
        # determine message length
        msg_length = len(message)
        length_bytes = msg_length.to_bytes(4, byteorder='big')

        # send the length of the message
        total = 0
        while total < 4:
            sent = self.peer_socket.send(length_bytes[total:])
            if sent == 0:
                raise MessengerRuntimeError("socket connection broken")
            total += sent

        # send the message itself
        total = 0
        while total < msg_length:
            sent = self.peer_socket.send(message[total:])
            if sent == 0:
                raise MessengerRuntimeError("socket connection broken")
            total += sent

        return total

    def receive(self):
        """
        Receives a secure JSON message and uses the cipher established during the handshake to decrypt it.
        :return: decrypted message
        """
        message = self.receive_raw()
        message = self.cipher.decrypt(message)
        message = message.decode('utf-8')
        message = json.loads(message)
        return message

    def send(self, message):
        """
        Send a secure JSON message by first encrypting the message using the cipher established during the handshake.
        :return: total bytes sent
        """
        message = json.dumps(message)
        message = message.encode('utf-8')
        message = self.cipher.encrypt(message)
        return self.send_raw(message)

    def request(self, request_message):
        """
        Performs a request which includes sending a message and waiting for the reply by the peer. If the peer
        encountered any errors while processing the request the reply contains an error. If that's the case a
        corresponding exception is triggered.
        :param request_message: the request message
        :return: the reply from the peer
        """
        self.send(request_message)
        reply_message = self.receive()

        if 'status' not in reply_message:
            raise MessengerInvalidUseException("malformed reply message: {}".format(reply_message))

        if reply_message['status'] == 'error':
            if reply_message['content'] == "protocol not supported":
                raise MessengerRuntimeError("error during request", request_message)

            elif reply_message['content'] == "malformed message":
                raise MessengerInvalidUseException("error during request: {}".format(request_message))

        return reply_message['content']

    def reply_ok(self, reply_message):
        """
        Send a reply message, indicating that no error has occurred.
        :param reply_message: the reply message
        :return: None
        """
        self.send({
            'status': 'ok',
            'content': reply_message
        })

    def reply_error(self, reply_message):
        """
        Sends a reply message, indicating that an error has occurred.
        :param reply_message: the reply message
        :return:
        """
        self.send({
            'status': 'error',
            'content': reply_message
        })

    def receive_attachment(self, destination_path):
        """
        Receives an attachment (i.e., a byte stream of arbitrary length) and writes it to disk.
        :param destination_path: the file path to which the byte stream is written to
        :return: total number of bytes received
        """
        # receive size information
        size = self.receive()['size']

        # write the byte stream in chunks to the destination
        with open(destination_path, 'wb') as f:
            total = 0
            while total < size:
                chunk = self.receive_raw()
                chunk = self.cipher.decrypt(chunk)
                f.write(chunk)

                total += len(chunk)

        return total

    def send_attachment(self, source_path, chunk_size=2048):
        """
        Sends an attachment (i.e., a byte stream of arbitrary length) by reading data from disk.
        :param source_path: the file path from which the byte stream is read
        :param chunk_size: size of the chunks to be sent (default: 2048)
        :return: total number of bytes sent (this is the actual number of bytes sent - not the size of the source)
        """
        # send size information
        size = os.path.getsize(source_path)
        self.send({
            'size': size
        })

        # read from the source and transfer in chunks
        with open(source_path, 'rb') as f:
            total = 0
            chunk = f.read(chunk_size)
            while chunk:
                data = self.cipher.encrypt(chunk)
                self.send_raw(data)
                total += len(data)
                chunk = f.read(chunk_size)

        return total
