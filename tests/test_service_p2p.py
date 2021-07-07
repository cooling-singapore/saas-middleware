import unittest

from saas.cryptography.messenger import SecureMessenger, MessengerRuntimeError, MessengerInvalidUseException, \
    MessengerException
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


if __name__ == '__main__':
    unittest.main()
