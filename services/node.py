"""
SaaS Node - manages P2P communication between nodes and keeps node-related keys.
"""

import os
import logging
import threading
import socket

from services.secure_messenger import SecureMessenger
from services.nodedb import NodeDB
from services.eckeypair import ECKeyPair

logger = logging.getLogger('Node')


class Node:
    def __init__(self, datastore_path):
        self.datastore_path = datastore_path
        self.key = None

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
            self.key = ECKeyPair.from_private_key_file(private_key_path, password)
            logger.info("existing identity found. using iid '{}' and public key:\n{}".format(self.key.iid, self.key.public_as_string()))

        else:
            # create a new private key
            self.key = ECKeyPair.create_new()
            self.key.write_private(private_key_path, password)
            logger.info("created new identity with iid '{}' and public key:\n{}".format(self.key.iid, self.key.public_as_string()))

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
                peer = messenger.handshake(self.key)

                self.handle_client(peer, messenger)

            except socket.timeout:
                pass

            except Exception as e:
                logger.error("error in server loop: {}".format(e))

        logger.info("stop listening to incoming connections")
        self.server_socket.close()

    def handle_client(self, peer, messenger):
        logger.info("begin serving client '{}'".format(peer.short_iid))

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
        logger.info("done serving client '{}'".format(peer.short_iid))
