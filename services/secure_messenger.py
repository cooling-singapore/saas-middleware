import os
import logging
import json
import base64

from services.eckeypair import ECKeyPair

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

logger = logging.getLogger('Messenger')


class SecureMessenger:
    def __init__(self, peer_socket):
        self.peer_socket = peer_socket
        self.peer = None
        self.cipher = None

    def handshake(self, node_key):
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

        # initialise the cipher
        self.cipher = Fernet(base64.urlsafe_b64encode(session_key))

        # exchange public keys
        self.send({'public_key': node_key.public_as_string(truncate=True)})
        self.peer = ECKeyPair.from_public_key_string(self.receive()['public_key'])

        return self.peer

    def close(self):
        self.peer_socket.close()
        self.peer_socket = None
        self.peer = None
        self.cipher = None

    def receive_raw(self):
        chunks = []
        received = 0
        while received < 4:
            chunk = self.peer_socket.recv(min(4 - received, 4))
            if chunk == b'':
                raise Exception("socket connection broken")

            chunks.append(chunk)
            received += len(chunk)

        msg_length_byte = b''.join(chunks)
        msg_length = int.from_bytes(msg_length_byte, 'big')

        chunks = []
        received = 0
        while received < msg_length:
            chunk = self.peer_socket.recv(min(msg_length - received, 2048))
            if chunk == b'':
                raise Exception("socket connection broken")

            chunks.append(chunk)
            received += len(chunk)

        message = b''.join(chunks)
        return message

    def send_raw(self, message):
        # determine message length
        msg_length = len(message)
        length_bytes = msg_length.to_bytes(4, byteorder='big')

        # send the length of the message
        total = 0
        while total < 4:
            sent = self.peer_socket.send(length_bytes[total:])
            if sent == 0:
                raise Exception("socket connection broken")
            total += sent

        # send the message itself
        total = 0
        while total < msg_length:
            sent = self.peer_socket.send(message[total:])
            if sent == 0:
                raise Exception("socket connection broken")
            total += sent

    def receive(self):
        message = self.receive_raw()
        message = self.cipher.decrypt(message)
        message = message.decode('utf-8')
        message = json.loads(message)
        return message

    def send(self, message):
        message = json.dumps(message)
        message = message.encode('utf-8')
        message = self.cipher.encrypt(message)
        self.send_raw(message)

    def request(self, message):
        self.send(message)
        return self.receive()

    def receive_attachment(self, destination_path):
        # receive size information
        size = self.receive()['size']

        with open(destination_path, 'wb') as f:
            total = 0
            while total < size:
                chunk = self.receive_raw()
                chunk = self.cipher.decrypt(chunk)
                f.write(chunk)

                total += len(chunk)

    def send_attachment(self, source_path, chunk_size=2048):
        # send size information
        size = os.path.getsize(source_path)
        self.send({
            'size': size
        })

        with open(source_path, 'rb') as f:
            chunk = f.read(chunk_size)
            while chunk:
                data = self.cipher.encrypt(chunk)
                self.send_raw(data)
                chunk = f.read(chunk_size)
