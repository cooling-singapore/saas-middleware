from __future__ import annotations

import math
import os
import json
import base64
import socket

from saas.cryptography.eckeypair import ECKeyPair
from saas.exceptions import PeerUnavailableError, ConnectionBrokenError, TransmissionError, P2PMessengerException, \
    HandshakeFailedError
from saas.keystore.identity import Identity

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

from saas.logging import Logging

logger = Logging.get('p2p.messenger')


class SecureMessenger:
    default_chunk_size = 2048

    """
    SecureMessenger is a wrapper for a TCP socket connection. It uses encryption to secure the communication between
    two nodes. For this purpose, a key exchange handshake is performed immediately upon establishing a connection.
    All message exchange henceforth is encrypted.
    """
    def __init__(self, peer_socket: socket):
        self._peer_socket = peer_socket
        self._peer = None
        self._cipher = None

    @classmethod
    def connect(cls, peer_address: (str, int), identity: Identity) -> (Identity, SecureMessenger):
        """
        Attempts to connect to a peer. If a connection is established, a handshake is performed between
        the peer and the counterparty (i.e., the node).
        :param peer_address: the address (host:port) of the peer
        :param identity: the identity of the peer's counterparty
        :return: the identity of the peer and the SecureMessenger object if successful.
        :except ConnectionRefusedError
        :except HandshakeFailedError
        """
        try:
            # try to establish a socket connection to the peer and create a messenger
            messenger = SecureMessenger(socket.create_connection(peer_address))
            peer = messenger._handshake(identity)
            return peer, messenger

        except ConnectionRefusedError:
            raise PeerUnavailableError(peer_address)

    @classmethod
    def accept(cls, peer_socket: socket.socket, identity: Identity) -> (Identity, SecureMessenger):
        """
        Attempts to accept an incoming connection from a peer. A handshake is performed between the peer
        and the counterparty (i.e., the node).
        :param peer_socket: the socket for the peer
        :param identity: the identity of the peer's counterparty
        :return: the identity of the peer and the SecureMessenger object if successful.
        :except HandshakeFailedError
        """
        messenger = SecureMessenger(peer_socket)
        peer = messenger._handshake(identity)
        return peer, messenger

    def close(self) -> None:
        """
        Closes the connection.
        :return: None
        """
        if self._peer_socket:
            self._peer_socket.close()
            self._peer_socket = None

    def send_object(self, content: dict) -> int:
        """
        Sends an object.
        :return: total bytes sent
        :except ConnectionBrokenError
        """

        # convert the content object into the message and encrypt it
        message = json.dumps(content)
        message = message.encode('utf-8')
        message = self.cipher.encrypt(message)

        # send the message
        length = len(message)
        total_sent = self._send_data(length.to_bytes(4, byteorder='big'))
        total_sent += self._send_data(message)

        return total_sent

    def receive_object(self) -> dict:
        """
        Receives an object.
        :return: object
        :except ConnectionBrokenError
        """

        # receive the message
        length = int.from_bytes(self._receive_data(4), 'big')
        message = self._receive_data(length)

        # decrypt and convert the message into the content object
        message = self.cipher.decrypt(message)
        message = message.decode('utf-8')
        content = json.loads(message)

        return content

    def send_stream(self, source: str, chunk_size: int = None) -> int:
        """
        Sends the contents of a file as a stream of data chunks.
        :param source: the path of the file from which the byte stream is read
        :param chunk_size: the size of the chunks the file is divided into
        :return: total bytes sent (this is the actual number of bytes sent - not the size of the file)
        :except FileNotFoundError
        :except ConnectionBrokenError
        """

        # does the file exist?
        if not os.path.isfile(source):
            raise FileNotFoundError()

        # determine the chunk size
        chunk_size = chunk_size if chunk_size else SecureMessenger.default_chunk_size

        # send the preamble
        file_size = os.path.getsize(source)
        preamble = {
            'content_size': file_size,
            'n_chunks': math.ceil(file_size / chunk_size)
        }
        total_sent = self.send_object(preamble)

        # read from the source and send the stream of chunks
        with open(source, 'rb') as f:
            # read a chunk and encrypt it
            chunk = f.read(chunk_size)
            while chunk:
                total_sent += self._send_chunk(chunk)
                chunk = f.read(chunk_size)

        return total_sent

    def receive_stream(self, destination: str) -> int:
        """
        Receives a stream of data chunks and stores them in a file.
        :param destination: the path of the file to which the byte stream is written
        :return: total bytes written to file (i.e., the file size)
        :except TransmissionError
        :except ConnectionBrokenError
        """

        # receive the preamble
        preamble = self.receive_object()
        if not all(p in preamble for p in ['content_size', 'n_chunks']):
            raise TransmissionError({
                'preamble': preamble
            })

        # read all the chunks and write the to the file
        total_written = 0
        with open(destination, 'wb') as f:
            for i in range(preamble['n_chunks']):
                chunk = self._receive_chunk()
                f.write(chunk)

                total_written += len(chunk)

        # verify if the bytes written is the correct file size
        if total_written != preamble['content_size']:
            raise TransmissionError({
                'preamble': preamble,
                'total_written': total_written
            })

        return total_written

    def _handshake(self, node: Identity) -> Identity:
        try:
            # generate an ephemeral key pair
            key = ECKeyPair.create_new()

            # send and receive peer public key information
            self._send_chunk(key.public_as_bytes())
            peer_key = ECKeyPair.from_public_key_bytes(self._receive_chunk())

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

            # exchange identities. note that this is not strictly speaking part of the handshake. it is merely for the
            # benefit of the peers to know who their counterparty is.
            self.send_object(node.serialise())
            self.peer = Identity.deserialise(self.receive_object())

            return self.peer

        except P2PMessengerException:
            raise HandshakeFailedError()

    def _send_data(self, data: bytes) -> int:
        total_sent = 0
        while total_sent < len(data):
            sent = self._peer_socket.send(data[total_sent:])
            if sent == 0:
                raise ConnectionBrokenError()
            total_sent += sent
        return total_sent

    def _receive_data(self, length: int) -> bytes:
        chunks = []
        received = 0
        while received < length:
            chunk = self._peer_socket.recv(min(length - received, SecureMessenger.default_chunk_size))
            if chunk == b'':
                raise ConnectionBrokenError()

            chunks.append(chunk)
            received += len(chunk)

        return b''.join(chunks)

    def _send_chunk(self, chunk: bytes) -> int:
        chunk = self._cipher.encrypt(chunk) if self._cipher else chunk
        chunk_length = len(chunk)
        total_sent = self._send_data(chunk_length.to_bytes(4, byteorder='big'))
        total_sent += self._send_data(chunk)
        return total_sent

    def _receive_chunk(self) -> bytes:
        chunk_length = int.from_bytes(self._receive_data(4), 'big')
        chunk = self._receive_data(chunk_length)
        chunk = self._cipher.decrypt(chunk) if self._cipher else chunk
        return chunk
