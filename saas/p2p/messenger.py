from __future__ import annotations

import math
import os
import json
import base64
import socket
from typing import Optional, Any

import snappy
from json import JSONDecodeError
from dataclasses import dataclass, is_dataclass

from saas.cryptography.eckeypair import ECKeyPair
from saas.helpers import generate_random_string
from saas.keystore.identity import Identity

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

from saas.logging import Logging
from saas.p2p.exceptions import ReceiveDataError, SendDataError, MalformedPreambleError, MismatchingBytesWrittenError, \
    ResourceNotFoundError, DecodingJSONError, EncodingJSONError, HandshakeFailedError, MalformedMessageError, \
    UnexpectedMessageTypeError, MismatchingRequestIdError, PeerUnavailableError, P2PException

logger = Logging.get('p2p.messenger')


class SecureMessage:
    class CustomEncoder(json.JSONEncoder):
        def default(self, obj):
            if is_dataclass(obj):
                return obj.__dict__
            return json.JSONEncoder.default(self, obj)

    @classmethod
    def decrypt(cls, message_bytes: bytes, cipher: Fernet) -> dict:
        message_str = cipher.decrypt(message_bytes).decode('utf-8')
        try:
            return json.loads(message_str)
        except JSONDecodeError as e:
            raise DecodingJSONError({
                'message': message_str,
                'e': e
            })

    def encrypt(self, cipher: Fernet) -> bytes:
        try:
            message_str = json.dumps(self, cls=self.CustomEncoder).encode('utf-8')
            return cipher.encrypt(message_str)
        except TypeError as e:
            raise EncodingJSONError({
                'content': self.__dict__,
                'e': e
            })


@dataclass
class SecureHandshake(SecureMessage):
    identity: dict


@dataclass
class SecureRequest(SecureMessage):
    type: str
    request_id: str
    content: Any
    has_attachment: bool

    @classmethod
    def create_request(cls, content, has_attachment: bool) -> SecureRequest:
        return cls(type="request", request_id=generate_random_string(16), content=content,
                   has_attachment=has_attachment)

    @classmethod
    def create_response(cls, request_id: str, content, has_attachment: bool) -> SecureRequest:
        return cls(type="response", request_id=request_id, content=content,
                   has_attachment=has_attachment)


@dataclass
class SecureStreamPreamble(SecureMessage):
    content_size: float
    n_chunks: int


class SecureMessenger:
    default_chunk_size = 2048

    """
    SecureMessenger is a wrapper for a TCP socket connection. It uses encryption to secure the communication between
    two nodes. For this purpose, a key exchange handshake is performed immediately upon establishing a connection.
    All message exchange henceforth is encrypted.
    """

    def __init__(self, peer_socket: socket, storage_path: str):
        self._peer_socket = peer_socket
        self._storage_path = storage_path
        self._cipher: Optional[Fernet] = None

    @classmethod
    def connect(cls, peer_address: (str, int), identity: Identity, storage_path: str) -> (Identity, SecureMessenger):
        """
        Attempts to connect to a peer by performing a handshake once the connection is established.
        :param peer_address: the address (host:port) of the peer
        :param identity: the identity of the peer's counterparty
        :param storage_path: path to where attachments are being stored
        :return: the identity of the peer and the SecureMessenger object if successful.
        :raise PeerUnavailableError
        :raise HandshakeFailedError
        """
        try:
            # try to establish a socket connection to the peer and create a messenger
            messenger = SecureMessenger(socket.create_connection(peer_address), storage_path)
            peer = messenger._handshake(identity)
            return peer, messenger

        except ConnectionRefusedError:
            raise PeerUnavailableError({
                'peer_address': peer_address
            })

    @classmethod
    def accept(cls, peer_socket: socket.socket, identity: Identity, storage_path: str) -> (Identity, SecureMessenger):
        """
        Attempts to accept an incoming connection from a peer by performing a handshake.
        :param peer_socket: the socket for the peer
        :param identity: the identity of the peer's counterparty
        :param storage_path: path to where attachments are being stored
        :return: the identity of the peer and the SecureMessenger object if successful.
        """
        messenger = SecureMessenger(peer_socket, storage_path)
        peer = messenger._handshake(identity)
        return peer, messenger

    def close(self) -> None:
        """
        Closes the connection.
        :return: None
        """
        if self._peer_socket:
            self._peer_socket.close()

    def send_request(self, content: Any, attachment_path: str = None) -> dict:
        """
        Sends a request and waits for a response.
        :param content: the request content
        :param attachment_path: (optional) path to an attachment that is sent as byte stream after the content
        :return: the response
        """

        # check if the attachment exists (if applicable)
        if attachment_path and not os.path.isfile(attachment_path):
            raise FileNotFoundError(f"attachment at {attachment_path} does not exist")

        # send the request content, followed by the attachment (if any)
        request = SecureRequest.create_request(content=content, has_attachment=attachment_path is not None)
        self._send_object(request)
        if attachment_path:
            self._send_stream(attachment_path)

        # receive the response and check if it is a valid response message
        response = SecureRequest(**self._receive_object())

        # required = ['type', 'request_id', 'content', 'has_attachment']
        # if not all(p in response for p in required):
        #     raise MalformedMessageError({
        #         'required': required,
        #         'response': response,
        #         'related_request': request
        #     })

        expected_type = 'response'
        if response.type != expected_type:
            raise UnexpectedMessageTypeError({
                'expected': expected_type,
                'response': response,
                'related_request': request
            })

        if response.request_id != request.request_id:
            raise MismatchingRequestIdError({
                'request': request,
                'response': response
            })

        # receive the attachment (if any)
        destination_path = None
        if response.has_attachment:
            destination_path = os.path.join(self._storage_path, f"attachment_{generate_random_string(16)}")
            self._receive_stream(destination_path)

        return {
            'content': response.content,
            'attachment': destination_path
        }

    def receive_request(self) -> dict:
        """
        Receives a request, i.e., a dict with the following keys: 'type', 'request_id', 'content', 'has_attachment'.
        :return: the request
        """
        request = SecureRequest(**self._receive_object())
        # required = ['type', 'request_id', 'content', 'has_attachment']
        # if not all(p in request for p in required):
        #     raise MalformedMessageError({
        #         'request': request,
        #         'required': required
        #     })

        expected_type = 'request'
        if request.type != expected_type:
            raise UnexpectedMessageTypeError({
                'expected': expected_type,
                'request': request
            })

        # receive the attachment (if any)
        destination_path = None
        if request.has_attachment:
            destination_path = os.path.join(self._storage_path, f"attachment_{generate_random_string(16)}")
            self._receive_stream(destination_path)

        return {
            'request_id': request.request_id,
            'content': request.content,
            'attachment': destination_path
        }

    def send_response(self, request_id: str, content: Any, attachment_path: str = None) -> None:
        """
        Sends a response to a previously received request.
        :param request_id: the id of the request this response is referring to
        :param content: the response content
        :param attachment_path: (optional) path to an attachment that is sent as byte stream after the content
        :return:
        """

        # check if the attachment exists (if applicable)
        if attachment_path and not os.path.isfile(attachment_path):
            raise ResourceNotFoundError({
                'attachment_path': attachment_path
            })

        # send the request content, followed by the attachment (if any)
        response = SecureRequest.create_response(request_id=request_id, content=content,
                                                 has_attachment=attachment_path is not None)
        self._send_object(response)
        if attachment_path:
            self._send_stream(attachment_path)

    def _handshake(self, identity: Identity) -> Identity:
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
            self._cipher = Fernet(base64.urlsafe_b64encode(session_key))

            # exchange identities. note that this is not strictly speaking part of the handshake. it is merely for the
            # benefit of the peers to know who their counterparty is.
            handshake = SecureHandshake(identity=identity.serialise())
            self._send_object(handshake)
            response = SecureHandshake(**self._receive_object())
            self.peer = Identity.deserialise(response.identity)

            return self.peer

        except P2PException as e:
            raise HandshakeFailedError({
                'e': e
            })

        except Exception as e:
            logger.error(f"unhandled non-SaaS exception: {e}")
            raise HandshakeFailedError({
                'e': e
            })

    def _send_object(self, message: SecureMessage) -> int:
        # convert the content object into the message and encrypt it
        encrypted_message = message.encrypt(self._cipher)

        # send the message
        length = len(encrypted_message)
        total_sent = self._send_data(length.to_bytes(4, byteorder='big'))
        total_sent += self._send_data(encrypted_message)
        return total_sent

    def _receive_object(self) -> dict:
        # receive the message
        length = int.from_bytes(self._receive_data(4), 'big')
        message = self._receive_data(length)

        # decrypt and convert the message into the content object
        message = self._cipher.decrypt(message)
        message = message.decode('utf-8')
        content = json.loads(message)

        return content

    def _send_stream(self, source: str, chunk_size: int = None) -> int:
        # does the file exist?
        if not os.path.isfile(source):
            raise ResourceNotFoundError({
                'source': source
            })

        # determine the chunk size
        chunk_size = chunk_size if chunk_size else SecureMessenger.default_chunk_size

        # send the preamble
        file_size = os.path.getsize(source)
        preamble = SecureStreamPreamble(content_size=file_size, n_chunks=math.ceil(file_size / chunk_size))
        total_sent = self._send_object(preamble)

        # read from the source and send the stream of chunks
        with open(source, 'rb') as f:
            # read a chunk and encrypt it
            chunk = f.read(chunk_size)
            while chunk:
                total_sent += self._send_chunk(chunk)
                chunk = f.read(chunk_size)

        return total_sent

    def _receive_stream(self, destination: str) -> int:
        # receive the preamble
        preamble = self._receive_object()
        required = ['content_size', 'n_chunks']
        if not all(p in preamble for p in required):
            raise MalformedPreambleError({
                'required': required,
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
            raise MismatchingBytesWrittenError({
                'preamble': preamble,
                'total_written': total_written
            })

        return total_written

    def _send_chunk(self, chunk: bytes) -> int:
        chunk = snappy.compress(chunk)
        chunk = self._cipher.encrypt(chunk) if self._cipher else chunk
        chunk_length = len(chunk)
        total_sent = self._send_data(chunk_length.to_bytes(4, byteorder='big'))
        total_sent += self._send_data(chunk)
        return total_sent

    def _receive_chunk(self) -> bytes:
        chunk_length = int.from_bytes(self._receive_data(4), 'big')
        chunk = self._receive_data(chunk_length)
        chunk = self._cipher.decrypt(chunk) if self._cipher else chunk
        chunk = snappy.decompress(chunk)
        return chunk

    def _send_data(self, data: bytes) -> int:
        total_sent = 0
        while total_sent < len(data):
            sent = self._peer_socket.send(data[total_sent:])
            if sent == 0:
                raise SendDataError({
                    'sent': sent,
                    'peer_socket': self._peer_socket,
                    'data': data,
                    'total_sent': total_sent,
                })
            total_sent += sent
        return total_sent

    def _receive_data(self, length: int) -> bytes:
        chunks = []
        received = 0
        while received < length:
            chunk = self._peer_socket.recv(min(length - received, SecureMessenger.default_chunk_size))
            if chunk == b'':
                raise ReceiveDataError({
                    'chunk': chunk,
                    'peer_socket': self._peer_socket,
                    'received': received,
                    'length': length,
                    'default_chunk_size': SecureMessenger.default_chunk_size
                })

            chunks.append(chunk)
            received += len(chunk)

        return b''.join(chunks)
