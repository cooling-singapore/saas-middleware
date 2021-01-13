"""
This module contains the code for the SaaS Node.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import os
import time
import logging
import threading
import socket
import traceback

from threading import Lock
from pathlib import Path

from saas.secure_messenger import SecureMessenger
from saas.registry.registry import Registry
from saas.registry.protocol import RegistryP2PProtocol
from saas.dor.dor import DataObjectRepository
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.rti.rti import RuntimeInfrastructure
from saas.nodedb.nodedb import NodeDB
from saas.nodedb.protocol import NodeDBP2PProtocol
from saas.eckeypair import ECKeyPair

logger = logging.getLogger('Node')


class Node:
    """
    Node provides the identity (i.e., keys) needed for various important cryptographic operations (e.g.,
    authentication and authorisation) as well as for providing a unique identified (i.e., iid which is a hash
    based on the public key part of the identity). Furthermore, Node manages the P2P communication between this
    node and its peers. For this purpose, it operates a TCP socket server which uses SecureMessenger to facilitate
    secure communication between the node and its peers. Node also encapsulates important components to realise the
    functionality required by the SaaS Middleware. These include the DOR (Data Object Repository) and RTI (RunTime
    Infrastructure) components. Node also keeps track of peers in the network using Registry. This class is
    thread-safe.
    """

    def __init__(self, name, datastore_path, rest_api_address):
        self.mutex = Lock()
        self.name = name
        self.key = None

        # initialise datastore
        self.datastore_path = datastore_path
        Path(datastore_path).mkdir(parents=True, exist_ok=True)

        # initialise server properties
        self.rest_api_address = rest_api_address
        self.server_address = None
        self.server_socket = None
        self.is_server_running = False
        self.is_server_stopped = False

        # initialise the registry
        self.registry = Registry(self)
        registry_protocol = RegistryP2PProtocol(self)

        # initialise the node database
        self.db = NodeDB(self)
        db_protocol = NodeDBP2PProtocol(self)

        # initialise the data object repository
        self.dor = DataObjectRepository(self)
        dor_protocol = DataObjectRepositoryP2PProtocol(self)

        # initialise the runtime infrastructure
        self.rti = RuntimeInfrastructure(self)

        # initialise messenger protocols
        self.msg_protocols = {
            registry_protocol.protocol_name: registry_protocol,
            db_protocol.protocol_name: db_protocol,
            dor_protocol.protocol_name: dor_protocol
        }

    def initialise_identity(self, password):
        """
        Initialises the identity of the node. A password is needed to protect the private key file stored on disk. If
        an identity already exists, it is used (i.e., the private key is loaded from disk). Otherwise, a new identity
        is created and the private key stored to disk. Public key and node iid are derived from the private key.
        :param password: the password that protects the private key file
        :return: None
        """
        self.mutex.acquire()

        # do we already have an identity? if so, load the private key from disk
        private_key_path = os.path.join(self.datastore_path, 'identity.pem')
        if os.path.isfile(private_key_path):
            self.key = ECKeyPair.from_private_key_file(private_key_path, password)
            logger.info(f"existing identity found. using iid '{self.key.iid}' and "
                        f"public key:\n{self.key.public_as_string(truncate=False)}")
        # if not, create a new one and store the private key to disk
        else:
            self.key = ECKeyPair.create_new()
            self.key.write_private(private_key_path, password)
            logger.info(f"created new identity with iid '{self.key.iid}' and "
                        f"public key:\n{self.key.public_as_string(truncate=False)}")
        self.mutex.release()

    def initialise_registry(self, boot_node_address):
        """
        Initialise the registry, i.e., add ourself to the registry and send a 'join' message to the boot node in order
        to join the domain.
        :param boot_node_address: the address of the boot node (host: port)
        :return:
        """
        # update the registry with information about ourself
        self.registry.update(self.key.iid, self.name, self.server_address, self.rest_api_address, [])

        # send a 'join' message to the boot node
        self.msg_protocols[RegistryP2PProtocol.id].send_join(boot_node_address)

    def start_server(self, server_address, concurrency=5):
        """
        Starts the TCP socket server at the specified address, allowing for some degree of concurrency. A separate
        thread is started for handling incoming connections.
        :param server_address: the bind address (host: port)
        :param concurrency: the degree of concurrency (default: 5)
        :return: None
        """
        self.mutex.acquire()
        if not self.server_socket:
            self.server_address = server_address

            # create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(self.server_address)
            self.server_socket.listen(concurrency)
            logger.info(f"server initialised at address '{self.server_address}'")

            # start the server thread
            thread = threading.Thread(target=self.handle_incoming_connections)
            thread.setDaemon(True)
            thread.start()
        self.mutex.release()

    def stop_server(self):
        """
        Instructs the server thread to stop accepting incoming connections and to shutdown the server socket. This
        may take a few seconds. Note: this method is blocking (i.e., it will return once the server has stopped).
        :return:
        """
        self.mutex.acquire()
        if self.server_socket:
            self.is_server_running = False
            while not self.is_server_stopped:
                logger.debug("waiting for server to be stopped...")
                time.sleep(2)
        self.mutex.release()

    def handle_incoming_connections(self):
        """
        Handles incoming connections and starts worker threads for every successfully established connection. Note
        that this method runs in a separate thread.
        :return: None
        """
        logger.info("start listening to incoming connections")

        # main loop for listening for incoming connections
        self.is_server_running = True
        self.server_socket.settimeout(5.0)

        while self.is_server_running:
            try:
                peer, messenger = SecureMessenger.accept_connection_by_peer(self)
                threading.Thread(target=self.handle_client, args=(peer, messenger)).start()

            except socket.timeout:
                pass

            except Exception as e:
                logger.error(f"error in server loop: {e}")

        logger.info("stop listening to incoming connections")

        self.server_socket.close()
        self.server_socket = None
        self.is_server_stopped = True

    def handle_client(self, peer, messenger):
        """
        Handles a client connection using the corresponding P2P protocol. Note that this method runs in its own
        thread.
        :param peer: the peer socket
        :param messenger: the messenger that facilitates communication between the node and the peer
        :return: None
        """
        logger.info(f"begin serving client '{peer.short_iid}'")

        # based on the first message received, determine the protocol and let the protocol handle all
        # further message exchanges
        try:
            # do we have a valid message?
            message = messenger.receive()
            if all(required in message for required in ['protocol', 'payload']):
                # get the protocol instance and handle the message
                protocol = self.msg_protocols[message['protocol']]
                if protocol:
                    # let the protocol handle this and subsequent messages for this session
                    protocol.handle_message(message, messenger)

                else:
                    logger.warning(f"ignoring message for unsupported protocol: {message}")
                    messenger.reply_error(501, "protocol not supported")

            else:
                logger.warning(f"ignoring malformed message: {message}")
                messenger.reply_error(400, "malformed message")

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            logger.error(f"error while serving client '{peer.short_iid}': {e}\n{trace}")

        messenger.close()
        logger.info(f"done serving client '{peer.short_iid}'")
