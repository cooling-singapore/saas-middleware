import unittest
import os
import logging
import time

from saas.node import Node
from saas.secure_messenger import SecureMessenger, MessengerRuntimeError, MessengerInvalidUseException

from tests.testing_environment import TestingEnvironment

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)
env = TestingEnvironment.get_instance('../config/testing-config.json')


class NodeTestCases(unittest.TestCase):
    def setUp(self):
        env.prepare_working_directory()

    def tearDown(self):
        pass

    def test_node_creation_and_initialisation(self):
        node = Node('test_node', env.wd_path, env.rest_api_address)

        # identity hasn't been initialised yet, so no key yet
        assert not node.key

        # server hasn't started yet, so no server socket
        assert not node.server_socket

        # initialise the identity, afterwards we should have a key, iid and short_iid
        node.initialise_identity(env.wd_path)
        assert node.key
        assert node.key.iid
        assert node.key.short_iid

        # start the node server
        node.start_server(env.p2p_server_address)
        assert node.server_socket

        time.sleep(5)
        node.stop_server()
        assert not node.server_socket

    def test_node_invalid_message(self):
        node0 = Node('node0', os.path.join(env.wd_path, 'node0'), env.rest_api_address)
        node0.initialise_identity(env.password)

        node1 = Node('node1', os.path.join(env.wd_path, 'node1'), env.rest_api_address)
        node1.initialise_identity(env.password)

        # start the node server
        node0.start_server(env.p2p_server_address)
        assert node0.server_socket

        # establish a connection and send a malformed message
        peer, messenger = SecureMessenger.connect_to_peer(env.p2p_server_address, node1)
        try:
            messenger.request({'asdasd': 'sdfds'})

        except MessengerRuntimeError:
            assert False

        except MessengerInvalidUseException:
            assert True

        else:
            assert False

        finally:
            messenger.close()

        # establish a connection and send a message indicating an unsupported protocol
        peer, messenger = SecureMessenger.connect_to_peer(env.p2p_server_address, node1)
        try:
            messenger.request({'protocol': 'sdfds'})

        except MessengerRuntimeError:
            assert False

        except MessengerInvalidUseException:
            assert True

        else:
            assert False

        finally:
            messenger.close()

        node0.stop_server()
        assert not node0.server_socket

    def test_node_unreachable(self):
        node0 = Node('node0', os.path.join(env.wd_path, 'node0'), env.rest_api_address)
        node0.initialise_identity(env.password)

        node1 = Node('node1', os.path.join(env.wd_path, 'node1'), env.rest_api_address)
        node1.initialise_identity(env.password)

        # start the node server
        node0.start_server(env.p2p_server_address)
        assert node0.server_socket

        # try to establish a connection to node0 but use the wrong port
        peer, messenger = SecureMessenger.connect_to_peer((env.p2p_server_address[0], env.p2p_server_address[1]+1), node1)
        assert not peer
        assert not messenger

        node0.stop_server()
        assert not node0.server_socket


if __name__ == '__main__':
    unittest.main()
