import logging
import os
import socket
import time
import unittest
from threading import Thread

from saas.cryptography.helpers import hash_file_content
from saas.keystore.identity import Identity
from saas.logging import Logging
from saas.p2p.exceptions import ReceiveDataError, PeerUnavailableError, MismatchingRequestIdError
from saas.p2p.messenger import SecureMessenger
from saas.keystore.keystore import Keystore
from saas.node import Node
from saas.p2p.protocol import P2PProtocol
from saas.p2p.service import P2PService
from tests.base_testcase import TestCaseBase


Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


class SimpleProtocol(P2PProtocol):
    def __init__(self, node):
        P2PProtocol.__init__(self, node, 'simple_protocol', {
            'bounce': self._handle_bounce
        })

    def send_bounce(self, peer_address: (str, int), value: str) -> dict:
        request = self.prepare_message('bounce', {'key': value})
        return self.request(peer_address, request)

    def _handle_bounce(self, request: dict, peer: Identity) -> dict:
        return self.prepare_message('bounce_reply', request)


class P2PServiceTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        name = 'node'
        self.keystore = Keystore.create(self.wd_path, name, f"{name}@somewhere.com", 'password')
        self.node = Node(self.keystore, self.wd_path)
        self.p2p_address = self.generate_p2p_address()
        self.service = P2PService(self.node, self.p2p_address)

    def tearDown(self):
        self.cleanup()

    def test_start_and_stop(self):
        self.service.start_service()
        self.service.stop_service()
        assert True

    def test_simple_protocol(self):
        protocol = SimpleProtocol(self.node)
        self.service.add(protocol)

        self.service.start_service()

        response, _ = protocol.send_bounce(self.p2p_address, '42')

        assert(response is not None)
        assert('key' in response and response['key'] == '42')

        self.service.stop_service()

    def test_invalid_messages(self):
        protocol = SimpleProtocol(self.node)
        self.service.add(protocol)

        self.service.start_service()

        # protocol not supported
        _, messenger = SecureMessenger.connect(self.p2p_address, self.node.identity(), self.wd_path)
        assert (messenger is not None)

        try:
            # prepare a message and then replace the protocol manually with something invalid
            message = protocol.prepare_message('msg_type', {'key': 'value'})
            message.protocol = 'alsjdfhskjdf'
            _ = messenger.send_request(message)
            assert False

        except ReceiveDataError:
            assert True

        except Exception:
            assert False

        finally:
            messenger.close()

        # message type not supported
        _, messenger = SecureMessenger.connect(self.p2p_address, self.node.identity(), self.wd_path)
        assert (messenger is not None)

        try:
            # prepare a message and then replace the protocol manually with something invalid
            message = protocol.prepare_message('invalid_msg_type', {'key': 'value'})
            _ = messenger.send_request(message)
            assert False

        except ReceiveDataError:
            assert True

        except Exception:
            assert False

        finally:
            messenger.close()

        self.service.stop_service()

    def test_unreachable(self):
        try:
            SecureMessenger.connect(self.p2p_address, self.node.identity(), self.wd_path)
            assert False

        except PeerUnavailableError:
            assert True

        except Exception:
            assert False


class SecureMessengerTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

    def tearDown(self):
        self.cleanup()

    def test_connect_accept(self):
        keystores = self.create_keystores(2)
        server_address = self.generate_p2p_address()
        wd_path = self.wd_path

        server_identity = keystores[0].identity
        client_identity = keystores[1].identity

        class TestServer(Thread):
            def run(self):
                # create server socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(server_address)
                server_socket.listen(1)

                peer_socket, peer_address = server_socket.accept()

                # create messenger and perform handshake
                server_peer_identity, server_messenger = SecureMessenger.accept(peer_socket, server_identity, wd_path)
                assert(server_peer_identity.id == client_identity.id)
                server_messenger.close()

                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = SecureMessenger.connect(server_address, client_identity, wd_path)
        assert(client_peer_identity.id == server_identity.id)
        client_messenger.close()

    def test_send_receive_object(self):
        keystores = self.create_keystores(2)
        server_address = self.generate_p2p_address()
        wd_path = self.wd_path

        server_identity = keystores[0].identity
        client_identity = keystores[1].identity

        ref_obj = {
            'key': 'value',
            'key2': 2
        }

        class TestServer(Thread):
            def run(self):
                # create server socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(server_address)
                server_socket.listen(1)

                peer_socket, peer_address = server_socket.accept()

                # create messenger and perform handshake
                server_peer_identity, server_messenger = SecureMessenger.accept(peer_socket, server_identity, wd_path)
                assert(server_peer_identity.id == client_identity.id)

                server_obj = server_messenger._receive_object()
                print(server_obj)
                assert(server_obj == ref_obj)
                server_messenger.close()

                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = SecureMessenger.connect(server_address, client_identity, wd_path)
        assert(client_peer_identity.id == server_identity.id)
        client_messenger._send_object(ref_obj)
        client_messenger.close()

    def test_send_receive_stream(self):
        wd_path = self.wd_path

        # generate some data
        source_path = os.path.join(self.wd_path, 'source.dat')
        destination_path = os.path.join(self.wd_path, 'destination.dat')
        file_size = 5*1024*1024
        self.generate_random_file(source_path, file_size)
        file_hash = hash_file_content(source_path).hex()

        keystores = self.create_keystores(2)
        server_address = self.generate_p2p_address()

        server_identity = keystores[0].identity
        client_identity = keystores[1].identity

        class TestServer(Thread):
            def run(self):
                # create server socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(server_address)
                server_socket.listen(1)

                peer_socket, peer_address = server_socket.accept()

                # create messenger and perform handshake
                server_peer_identity, server_messenger = SecureMessenger.accept(peer_socket, server_identity, wd_path)
                assert(server_peer_identity.id == client_identity.id)

                server_file_size = server_messenger._receive_stream(destination_path)
                assert(server_file_size == file_size)

                server_file_hash = hash_file_content(destination_path).hex()
                assert(server_file_hash == file_hash)

                server_messenger.close()
                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = SecureMessenger.connect(server_address, client_identity, wd_path)
        assert(client_peer_identity.id == server_identity.id)
        client_messenger._send_stream(source_path)

        client_messenger.close()

    def test_send_receive_request(self):
        keystores = self.create_keystores(2)
        server_address = self.generate_p2p_address()
        wd_path = self.wd_path

        server_identity = keystores[0].identity
        client_identity = keystores[1].identity

        class TestServer(Thread):
            def run(self):
                # create server socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(server_address)
                server_socket.listen(1)

                peer_socket, peer_address = server_socket.accept()

                # create messenger and perform handshake
                server_peer_identity, server_messenger = SecureMessenger.accept(peer_socket, server_identity, wd_path)
                assert(server_peer_identity.id == client_identity.id)

                request = server_messenger.receive_request()
                assert('question' in request['content'])
                logger.debug(f"request received: {request}")

                server_messenger.send_response(request['request_id'], {
                    'answer': '42'
                })
                server_messenger.close()

                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = SecureMessenger.connect(server_address, client_identity, wd_path)
        assert(client_peer_identity.id == server_identity.id)

        response = client_messenger.send_request({
            'question': 'What is the answer to the ultimate question of life, the universe and everything?'
        })

        logger.debug(f"response received: {response}")
        assert('answer' in response['content'])
        assert(response['content']['answer'] == '42')

        client_messenger.close()

    def test_send_receive_request_invalid_request_id(self):
        keystores = self.create_keystores(2)
        server_address = self.generate_p2p_address()
        wd_path = self.wd_path

        server_identity = keystores[0].identity
        client_identity = keystores[1].identity

        class TestServer(Thread):
            def run(self):
                # create server socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(server_address)
                server_socket.listen(1)

                peer_socket, peer_address = server_socket.accept()

                # create messenger and perform handshake
                server_peer_identity, server_messenger = SecureMessenger.accept(peer_socket, server_identity, wd_path)
                assert(server_peer_identity.id == client_identity.id)

                request = server_messenger.receive_request()
                assert('question' in request['content'])
                logger.debug(f"request received: {request}")

                server_messenger.send_response('invalid_request_id', {
                    'answer': '42'
                })
                server_messenger.close()

                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = SecureMessenger.connect(server_address, client_identity, wd_path)
        assert(client_peer_identity.id == server_identity.id)

        try:
            client_messenger.send_request({
                'question': 'What is the answer to the ultimate question of life, the universe and everything?'
            })
            assert False

        except MismatchingRequestIdError:
            assert True

        client_messenger.close()


if __name__ == '__main__':
    unittest.main()
