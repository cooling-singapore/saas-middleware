import os
import logging
import json
import base64
import socket

from saas.cryptography.eckeypair import ECKeyPair
from saas.utilities.general_helpers import all_in_dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

logger = logging.getLogger('cryptography.messenger')


class MessengerException(Exception):
    """
    MessengerException is the base class for all messenger-related exception classes.
    """
    def __init__(self, info, status=None):
        super().__init__()
        self.info = info
        self.status = status


class MessengerRuntimeError(MessengerException):
    """
    MessengerRuntimeError indicates that there has been an error during runtime.
    """
    def __init__(self, info, status=None):
        super().__init__(info)
        self.status = status


class MessengerInvalidUseException(MessengerException):
    """
    MessengerInvalidUseException indicates that the messenger is used in an invalid way. This kind of error
    indicates that the cause of the problem may be due to a bug or programming error in the code. In other
    words this exception indicates that a situation has occurred that shouldn't be possible.
    """
    def __init__(self, info):
        super().__init__(info)


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
        :param self_node: the counterparty for the peer (i.e., the db that wants to connect to the peer)
        :param expected_peer_iid: the (optional) expected iid for the peer at the given address. If peer iid and
        expected iid do not match, a warning message is produced in the log.
        :return: the messenger that facilitates communication between the db and the peer
        """
        try:
            peer_socket = socket.create_connection(peer_address)
            messenger = SecureMessenger(peer_socket)
            peer = messenger.handshake(self_node)
            logger.info(f"connected to peer '{peer.iid}'")

            # if we have an expected peer iid, do a comparison if it matches with what the peer is telling us
            if expected_peer_iid and not expected_peer_iid == peer.iid:
                logger.warning(f"unexpected iid for peer at address {peer_address}: "
                               f"expected={expected_peer_iid} idd_as_per_peer={peer.iid}")

            return peer, messenger

        except ConnectionRefusedError:
            logger.warning(f"cannot connect to peer at address '{peer_address}'")
            return None, None

    def handshake(self, node):
        """
        Performs the handshake (i.e., key exchange) in order to secure all further message exchange.
        :param node: the db that represents the counterparty to the handshake with the peer
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
            info=None,
            backend=default_backend()
        ).derive(shared_key)

        # initialise the cipher used to encrypt/decrypt messages
        self.cipher = Fernet(base64.urlsafe_b64encode(session_key))

        # exchange public keys. note that this is not strictly speaking part of the handshake. it is merely for the
        # benefit of the peers to know who their counterparty is.
        self.send({'public_key': node.identity().public_as_string()})
        self.peer = ECKeyPair.from_public_key_string(self.receive()['public_key'])

        return self.peer

    def close(self):
        """
        Closes the connection.
        :return: None
        """
        if self.peer_socket:
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
        :return: the reply (status, content) from the peer
        """
        self.send(request_message)
        reply = self.receive()

        if not all_in_dict(['status', 'content'], reply):
            raise MessengerException(f"malformed reply: {reply}")

        elif not reply['status'] == 200:
            raise MessengerException(reply['content'], reply['status'])

        else
            return reply['content']

    def reply_ok(self, reply_content=None):
        """
        Send a reply message, indicating that no error has occurred.
        :param reply_content: the reply content
        :return: None
        """
        self.send({
            'status': 200,
            'content': reply_content
        })

    def reply_error(self, status, reply_message):
        """
        Sends a reply message, indicating that an error has occurred.
        :param status: the status (based on https://restfulapi.net/http-status-codes/)
        :param reply_message: the reply message
        :return:
        """
        self.send({
            'status': status,
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
