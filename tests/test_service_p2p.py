import os
import socket
import time
import unittest
from threading import Thread

from saas.cryptography.hashing import hash_file_content
from saas.p2p.messenger import SecureMessenger
from saas.keystore.keystore import Keystore
from saas.node import Node
from saas.p2p.protocol import P2PProtocol
from saas.p2p.service import P2PService
from tests.base_testcase import TestCaseBase


class SimpleProtocol(P2PProtocol):
    def __init__(self, node):
        P2PProtocol.__init__(self, node, 'simple_protocol', {
            'bounce': self.bounce
        })

    def bounce(self, message, messenger):
        messenger.reply_ok(self.prepare_message('bounce_reply', message))


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

        # valid message
        _, messenger = SecureMessenger.connect_to_peer(self.p2p_address, self.node)
        assert(messenger is not None)
        message = protocol.prepare_message('bounce', 'test')
        reply = messenger.request(message)
        assert(reply is not None)
        assert(reply['type'] == 'bounce_reply')
        assert(reply['payload'] == 'test')

        self.service.stop_service()

    def test_invalid_messages(self):
        protocol = SimpleProtocol(self.node)
        self.service.add(protocol)

        self.service.start_service()

        # message malformed message
        _, messenger = SecureMessenger.connect_to_peer(self.p2p_address, self.node)
        assert (messenger is not None)

        try:
            message = "sdfsdfsdfs"
            messenger.request(message)
            assert False

        except MessengerException as e:
            assert(e.info == 'malformed message')

        finally:
            messenger.close()

        # protocol not supported
        _, messenger = SecureMessenger.connect_to_peer(self.p2p_address, self.node)
        assert (messenger is not None)

        try:
            message = protocol.prepare_message('blub', 'test')
            message['protocol'] = 'alsjdfhskjdf'
            messenger.request(message)
            assert False

        except MessengerException as e:
            assert(e.info == 'protocol not supported')

        finally:
            messenger.close()

        # message type not supported
        _, messenger = SecureMessenger.connect_to_peer(self.p2p_address, self.node)
        assert (messenger is not None)

        try:
            message = protocol.prepare_message('beee', 'test')
            messenger.request(message)
            assert False

        except MessengerException as e:
            assert(e.info == 'message type not supported')

        finally:
            messenger.close()

        self.service.stop_service()

    def test_unreachable(self):
        # valid message
        _, messenger = SecureMessenger.connect_to_peer(self.p2p_address, self.node)
        assert(messenger is None)


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
                server_peer_identity, server_messenger = SecureMessenger.accept(peer_socket, server_identity)
                assert(server_peer_identity.id == client_identity.id)
                server_messenger.close()

                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = SecureMessenger.connect(server_address, client_identity)
        assert(client_peer_identity.id == server_identity.id)
        client_messenger.close()

    def test_send_receive_object(self):
        keystores = self.create_keystores(2)
        server_address = self.generate_p2p_address()

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
                server_peer_identity, server_messenger = SecureMessenger.accept(peer_socket, server_identity)
                assert(server_peer_identity.id == client_identity.id)

                server_obj = server_messenger.receive_object()
                print(server_obj)
                assert(server_obj == ref_obj)
                server_messenger.close()

                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = SecureMessenger.connect(server_address, client_identity)
        assert(client_peer_identity.id == server_identity.id)
        client_messenger.send_object(ref_obj)
        client_messenger.close()

    def test_send_receive_stream(self):
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
                server_peer_identity, server_messenger = SecureMessenger.accept(peer_socket, server_identity)
                assert(server_peer_identity.id == client_identity.id)

                server_file_size = server_messenger.receive_stream(destination_path)
                assert(server_file_size == file_size)

                server_file_hash = hash_file_content(destination_path).hex()
                assert(server_file_hash == file_hash)

                server_messenger.close()
                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = SecureMessenger.connect(server_address, client_identity)
        assert(client_peer_identity.id == server_identity.id)
        client_messenger.send_stream(source_path)

        client_messenger.close()




if __name__ == '__main__':
    unittest.main()
