
"""
SaaS Node - manages P2P communication between nodes and keeps node-related keys.
"""

import os
import logging
import json
import threading
import socket
import base64

from utilities import serialize_public_key
from utilities import deserialize_public_key
from utilities import serialize_private_key
from utilities import deserialize_private_key
from utilities import create_private_key
from utilities import hash_bytes_object

from nodedb import NodeDB

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

logger = logging.getLogger('Node')


def generate_truncated_node_id(node_id):
    return "{}...{}".format(node_id[:4], node_id[-4:])


class SecureMessenger:
    def __init__(self, peer):
        self.peer = peer
        self.peer_id = None
        self.cipher = None

    def handshake(self, node_id):
        # generate keys for ourself
        self_private_key = ec.generate_private_key(ec.SECP384R1())
        self_public_key = self_private_key.public_key()

        # send self and receive peer public key information
        self.send_raw(serialize_public_key(self_public_key))
        peer_public_key = deserialize_public_key(self.receive_raw())

        # generate the shared key
        shared_key = self_private_key.exchange(ec.ECDH(), peer_public_key)
        session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None
        ).derive(shared_key)

        # initialise the cipher
        self.cipher = Fernet(base64.urlsafe_b64encode(session_key))

        # send self node id and receive peer node id
        self.send({'node_id': node_id})
        return self.receive()['node_id']

    def close(self):
        self.peer.close()
        self.peer = None
        self.peer_id = None
        self.cipher = None

    def receive_raw(self):
        chunks = []
        received = 0
        while received < 4:
            chunk = self.peer.recv(min(4 - received, 4))
            if chunk == b'':
                raise Exception("socket connection broken")

            chunks.append(chunk)
            received += len(chunk)

        msg_length_byte = b''.join(chunks)
        msg_length = int.from_bytes(msg_length_byte, 'big')

        chunks = []
        received = 0
        while received < msg_length:
            chunk = self.peer.recv(min(msg_length - received, 2048))
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
            sent = self.peer.send(length_bytes[total:])
            if sent == 0:
                raise Exception("socket connection broken")
            total += sent

        # send the message itself
        total = 0
        while total < msg_length:
            sent = self.peer.send(message[total:])
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


class Node:
    def __init__(self, datastore_path, custodian_key=None):
        # initialise some properties
        self.datastore_path = datastore_path
        # self.dor = None
        # self.rti = None
        # self.custodian_key = custodian_key

        # initialise identity properties
        self.private_key = None
        self.public_key = None
        self.id = None
        self.short_id = None

        # initialise server properties
        self.server_address = None
        self.server_socket = None
        self.is_server_running = False

        # create database
        self.db = NodeDB(datastore_path)

    def initialise_identity(self, password):
        # do we already have an identity (i.e., a public/private key pair)
        private_key_path = os.path.join(self.datastore_path, 'identity.pem')
        if os.path.isfile(private_key_path):
            # read the private key
            with open(private_key_path, "rb") as f:
                data = f.read()
                logger.info("existing identity found:\n{}".format(data.decode('utf-8')))
                self.private_key = deserialize_private_key(data, password)

        else:
            # create a new private key
            self.private_key = create_private_key()

            # write the private key
            with open(private_key_path, 'wb') as f:
                data = serialize_private_key(self.private_key, password)
                logger.info("created new identity:\n{}".format(data.decode('utf-8')))
                f.write(data)

        # obtain the public key and determine the node id
        # TODO: id generation should probably follow existing P2P system. for example, have a look here:
        # https://medium.com/textileio/how-ipfs-peer-nodes-identify-each-other-on-the-distributed-web-8b5b6476aa5e
        self.public_key = self.private_key.public_key()
        self.id = hash_bytes_object(serialize_public_key(self.public_key)).hex()
        self.short_id = generate_truncated_node_id(self.id)
        logger.info("using id '{}' and public key:\n{}".format(self.id, serialize_public_key(self.public_key).decode('utf-8')))

    def start_server(self, server_address, concurrency=5):
        self.server_address = server_address

        # create server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(self.server_address)
        self.server_socket.listen(concurrency)
        logger.info("server initialised at address '{}'".format(self.server_address))

        # start the server thread
        threading.Thread(target=self.handle_incoming_connections).start()

    def stop_server(self):
        self.is_server_running = False

    def handle_incoming_connections(self):
        logger.info("start listening to incoming connections")

        # main loop for listening for incoming connections
        self.is_server_running = True
        self.server_socket.settimeout(5.0)
        while self.is_server_running:
            try:
                # accept incoming connection and create messenger
                client, address = self.server_socket.accept()
                messenger = SecureMessenger(client)
                peer_id = messenger.handshake(self.id)

                self.handle_client(peer_id, messenger)

            except socket.timeout:
                pass

            except Exception as e:
                logger.error("error in server loop: {}".format(e))

        logger.info("stop listening to incoming connections")
        self.server_socket.close()

    def handle_client(self, peer_id, messenger):
        short_peer_id = generate_truncated_node_id(peer_id)
        logger.info("begin serving client '{}'".format(short_peer_id))

        # what does the client want?
        message = messenger.receive()
        logger.info("message received: {}".format(message))

        if 'request' not in message:
            logger.error("malformed message: {}".format(message))

        elif message['request'] == 'fetch':
            obj_id = message['obj_id']

            # check if we have the data object
            record = self.db.get_data_object_by_id(obj_id)
            source_path = os.path.join(self.datastore_path, "{}.content".format(record['c_hash']))
            if os.path.isfile(source_path):
                messenger.send({
                    'reply': 'found',
                    'obj_id': obj_id
                })

                messenger.send_attachment(source_path)

            else:
                messenger.send({
                    'reply': 'not found',
                    'obj_id': obj_id
                })

        elif message['request'] == 'migrate':
            pass

        else:
            logger.error("unsupported request '{}': message={}".format(message['request'], message))

        messenger.close()
        logger.info("done serving client '{}'".format(short_peer_id))

    # def export_custodian_public_key(self):
    #     # do we have a custodian key in the first place?
    #     if self.custodian_key is None:
    #         return None
    #
    #     # try to export the custodian key
    #     try:
    #         result = subprocess.check_output(['gpg', '--armor', '--export', self.custodian_key])
    #         result = result.decode('utf-8')
    #         return result
    #
    #     except subprocess.CalledProcessError as e:
    #         raise Exception("error while exporting custodian public key '{}': {}".format(self.custodian_key, e))
