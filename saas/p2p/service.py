import time
import logging
import threading
import socket
import traceback

from threading import Lock

from saas.p2p.protocol import SecureMessenger

logger = logging.getLogger('p2p.service')


class P2PService:
    def __init__(self, node, address):
        self._mutex = Lock()
        self._node = node
        self._address = address
        self._p2p_service_socket = None
        self._is_server_running = False
        self._is_server_stopped = True
        self._registered_protocols = {}

    def add(self, protocol):
        with self._mutex:
            logger.info(f"add support for p2p protocol '{protocol.name()}'")
            self._registered_protocols[protocol.name()] = protocol

    def address(self):
        return self._address

    def start_service(self, concurrency=5):
        """
        Starts the TCP socket server at the specified address, allowing for some degree of concurrency. A separate
        thread is started for handling incoming connections.
        :param server_address: the bind address (host:port)
        :param concurrency: the degree of concurrency (default: 5)
        :return: None
        """
        with self._mutex:
            if not self._p2p_service_socket:
                # create server socket
                self._p2p_service_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._p2p_service_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._p2p_service_socket.bind(self._address)
                self._p2p_service_socket.listen(concurrency)
                logger.info(f"server initialised at address '{self._address}'")

                # start the server thread
                thread = threading.Thread(target=self._handle_incoming_connections)
                thread.setDaemon(True)
                thread.start()

    def stop_service(self):
        """
        Instructs the server thread to stop accepting incoming connections and to shutdown the server socket. This
        may take a few seconds. Note: this method is blocking (i.e., it will return once the server has stopped).
        :return:
        """
        with self._mutex:
            if self._p2p_service_socket:
                self._is_server_running = False
                while not self._is_server_stopped:
                    logger.debug("waiting for server to be stopped...")
                    time.sleep(2)

    def _handle_incoming_connections(self):
        """
        Handles incoming connections and starts worker threads for every successfully established connection. Note
        that this method runs in a separate thread.
        :return: None
        """
        logger.info("start listening to incoming connections")

        # main loop for listening for incoming connections
        self._is_server_running = True
        self._is_server_stopped = False
        self._p2p_service_socket.settimeout(2.0)

        while self._is_server_running:
            try:
                # accept incoming connection
                peer_socket, peer_address = self._p2p_service_socket.accept()

                # create messenger and perform handshake
                messenger = SecureMessenger(peer_socket)
                peer = messenger.handshake(self._node)
                logger.info(f"connected by peer '{peer.iid}'")

                # start handling the client requests
                threading.Thread(target=self._handle_client, args=(peer, messenger)).start()

            except socket.timeout:
                pass

            except Exception as e:
                logger.error(f"error in server loop: {e}")

        logger.info("stop listening to incoming connections")

        self._p2p_service_socket.close()
        self._p2p_service_socket = None
        self._is_server_stopped = True

    def _handle_client(self, peer, messenger):
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
            if all(required in message for required in ['protocol', 'type', 'payload']):
                if not message['protocol'] in self._registered_protocols:
                    logger.warning(f"ignoring message for unsupported protocol: {message}")
                    messenger.reply_error(501, "protocol not supported")

                else:
                    # is the message type supported?
                    protocol = self._registered_protocols[message['protocol']]
                    if protocol.supports(message['type']):
                        # let the protocol handle this and subsequent messages for this session
                        protocol.handle_message(message, messenger)

                    else:
                        logger.warning(f"ignoring message for unsupported message type: {message}")
                        messenger.reply_error(501, "message type not supported")

            else:
                logger.warning(f"ignoring malformed message: {message}")
                messenger.reply_error(400, "malformed message")

        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            logger.error(f"error while serving client '{peer.short_iid}': {e}\n{trace}")

        messenger.close()
        logger.info(f"done serving client '{peer.short_iid}'")
