import logging
import os
import socket
import time
import unittest
from threading import Thread
from typing import Optional

from pydantic import BaseModel
from saascore.cryptography.helpers import hash_file_content
from saascore.keystore.identity import Identity
from saascore.log import Logging

from saas.p2p.exceptions import ReceiveDataError, PeerUnavailableError, MismatchingRequestIdError
from saas.p2p.messenger import SecureMessenger, P2PMessage
from saascore.keystore.keystore import Keystore
from saas.node import Node
from saas.p2p.protocol import P2PProtocol
from saas.p2p.service import P2PService
from tests.base_testcase import TestCaseBase, PortMaster

Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


class Bounce(BaseModel):
    value: str
    bounced_to: Optional[Identity]


class SimpleProtocol(P2PProtocol):
    def __init__(self, node):
        P2PProtocol.__init__(self, node, 'simple_protocol', {
            'bounce': (self._handle_bounce, Bounce)
        })

    def send_bounce(self, peer_address: (str, int), value: str) -> P2PMessage:
        request = self.prepare_message('bounce', Bounce(value=value))
        return self.request(peer_address, request)

    def _handle_bounce(self, message: Bounce, peer: Identity) -> P2PMessage:
        message.bounced_to = peer
        return self.prepare_message('bounce_reply', message)


class P2PServiceTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        name = 'node'
        self.keystore = Keystore.create(self.wd_path, name, f"{name}@somewhere.com", 'password')
        self.node = Node(self.keystore, self.wd_path)
        self.p2p_address = PortMaster.generate_p2p_address()
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
        content = Bounce.parse_obj(response.content)
        assert(content.value == '42')
        assert(content.bounced_to.id == self.node.identity.id)

        self.service.stop_service()

    def test_invalid_messages(self):
        protocol = SimpleProtocol(self.node)
        self.service.add(protocol)

        self.service.start_service()

        # protocol not supported
        _, messenger = SecureMessenger.connect(self.p2p_address, self.node.identity, self.wd_path)
        assert (messenger is not None)

        try:
            # prepare a message and then replace the protocol manually with something invalid
            message = protocol.prepare_message('msg_type', Bounce(value='23'))
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
        _, messenger = SecureMessenger.connect(self.p2p_address, self.node.identity, self.wd_path)
        assert (messenger is not None)

        try:
            # prepare a message and then replace the protocol manually with something invalid
            message = protocol.prepare_message('invalid_msg_type', Bounce(value='23'))
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
            SecureMessenger.connect(self.p2p_address, self.node.identity, self.wd_path)
            assert False

        except PeerUnavailableError:
            assert True

        except Exception:
            assert False


class SecureMessengerTestCase(unittest.TestCase, TestCaseBase):
    _server_identity = None
    _client_identity = None

    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        if SecureMessengerTestCase._server_identity is None:
            keystores = self.create_keystores(2)
            SecureMessengerTestCase._server_identity = keystores[0].identity
            SecureMessengerTestCase._client_identity = keystores[1].identity

    def tearDown(self):
        self.cleanup()

    def test_connect_accept(self):
        wd_path = self.wd_path
        server_address = PortMaster.generate_p2p_address()

        class TestServer(Thread):
            def run(self):
                # create server socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(server_address)
                server_socket.listen(1)

                peer_socket, peer_address = server_socket.accept()

                # create messenger and perform handshake
                server_peer_identity, server_messenger = \
                    SecureMessenger.accept(peer_socket, SecureMessengerTestCase._server_identity, wd_path)
                assert(server_peer_identity.id == SecureMessengerTestCase._client_identity.id)
                server_messenger.close()

                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = \
            SecureMessenger.connect(server_address, self._client_identity, wd_path)
        assert(client_peer_identity.id == self._server_identity.id)
        client_messenger.close()

    def test_send_receive_object(self):
        wd_path = self.wd_path
        server_address = PortMaster.generate_p2p_address()

        class TestMessage(BaseModel):
            key1: str
            key2: int

        ref_obj = TestMessage(key1='value', key2=2)

        class TestServer(Thread):
            def run(self):
                # create server socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(server_address)
                server_socket.listen(1)

                peer_socket, peer_address = server_socket.accept()

                # create messenger and perform handshake
                server_peer_identity, server_messenger = \
                    SecureMessenger.accept(peer_socket, SecureMessengerTestCase._server_identity, wd_path)
                # FIXME: Assertions do not work for threads in test
                assert(server_peer_identity.id == SecureMessengerTestCase._client_identity.id)

                server_obj = TestMessage.parse_obj(server_messenger._receive_object())
                print(server_obj)
                assert(server_obj == ref_obj)
                server_messenger.close()

                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = SecureMessenger.connect(server_address, self._client_identity, wd_path)
        assert(client_peer_identity.id == self._server_identity.id)
        client_messenger._send_object(ref_obj.dict())
        client_messenger.close()

    def test_send_receive_stream(self):
        wd_path = self.wd_path
        server_address = PortMaster.generate_p2p_address()

        # generate some data
        source_path = os.path.join(self.wd_path, 'source.dat')
        destination_path = os.path.join(self.wd_path, 'destination.dat')
        file_size = 5*1024*1024
        self.generate_random_file(source_path, file_size)
        file_hash = hash_file_content(source_path).hex()

        class TestServer(Thread):
            def run(self):
                # create server socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(server_address)
                server_socket.listen(1)

                peer_socket, peer_address = server_socket.accept()

                # create messenger and perform handshake
                server_peer_identity, server_messenger = \
                    SecureMessenger.accept(peer_socket, SecureMessengerTestCase._server_identity, wd_path)
                assert(server_peer_identity.id == SecureMessengerTestCase._client_identity.id)

                server_file_size = server_messenger._receive_stream(destination_path)
                assert(server_file_size == file_size)

                server_file_hash = hash_file_content(destination_path).hex()
                assert(server_file_hash == file_hash)

                server_messenger.close()
                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = SecureMessenger.connect(server_address, self._client_identity, wd_path)
        assert(client_peer_identity.id == self._server_identity.id)
        client_messenger._send_stream(source_path)

        client_messenger.close()

    def test_send_receive_request(self):
        wd_path = self.wd_path
        server_address = PortMaster.generate_p2p_address()

        class TestServer(Thread):
            def run(self):
                # create server socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(server_address)
                server_socket.listen(1)

                peer_socket, peer_address = server_socket.accept()

                # create messenger and perform handshake
                server_peer_identity, server_messenger = \
                    SecureMessenger.accept(peer_socket, SecureMessengerTestCase._server_identity, wd_path)
                assert(server_peer_identity.id == SecureMessengerTestCase._client_identity.id)

                request: P2PMessage = server_messenger.receive_request()
                assert(request.type == 'Q')
                assert('question' in request.content)
                logger.debug(f"request received: {request}")

                server_messenger.send_response(P2PMessage.parse_obj({
                    'sequence_id': request.sequence_id,
                    'protocol': request.protocol,
                    'type': 'A',
                    'content': {'answer': '42'}
                }))
                server_messenger.close()

                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = SecureMessenger.connect(server_address, self._client_identity, wd_path)
        assert(client_peer_identity.id == self._server_identity.id)

        response = client_messenger.send_request(P2PMessage.parse_obj({
            'protocol': 'Hitchhiker',
            'type': 'Q',
            'content': {'question': 'What is the answer to the ultimate question of life, the universe and everything?'}
        }))

        logger.debug(f"response received: {response}")
        assert(response.type == 'A')
        assert('answer' in response.content)
        assert(response.content['answer'] == '42')

        client_messenger.close()

    def test_send_receive_request_invalid_request_id(self):
        wd_path = self.wd_path
        server_address = PortMaster.generate_p2p_address()

        class TestServer(Thread):
            def run(self):
                # create server socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(server_address)
                server_socket.listen(1)

                peer_socket, peer_address = server_socket.accept()

                # create messenger and perform handshake
                server_peer_identity, server_messenger = \
                    SecureMessenger.accept(peer_socket, SecureMessengerTestCase._server_identity, wd_path)
                assert(server_peer_identity.id == SecureMessengerTestCase._client_identity.id)

                request: P2PMessage = server_messenger.receive_request()
                assert(request.type == 'Q')
                assert('question' in request.content)
                logger.debug(f"request received: {request}")

                server_messenger.send_response(P2PMessage.parse_obj({
                    'sequence_id': 99,
                    'protocol': request.protocol,
                    'type': 'A',
                    'content': {'answer': '42'}
                }))
                server_messenger.close()

                server_socket.close()

        server = TestServer()
        server.start()
        time.sleep(1)

        client_peer_identity, client_messenger = SecureMessenger.connect(server_address, self._client_identity, wd_path)
        assert(client_peer_identity.id == self._server_identity.id)

        try:
            client_messenger.send_request(P2PMessage.parse_obj({
                'protocol': 'Hitchhiker',
                'type': 'Q',
                'content': {
                    'question': 'What is the answer to the ultimate question of life, the universe and everything?'}
            }))
            assert False

        except MismatchingRequestIdError:
            assert True

        client_messenger.close()


if __name__ == '__main__':
    unittest.main()
