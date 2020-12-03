import unittest
import logging
import sqlite3
import os
import time
import json
import requests
import os
import logging
import time
import socket

from saas.node import Node
from saas.secure_messenger import SecureMessenger, MessengerRuntimeError, MessengerInvalidUseException

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)
datastore_path = '/Users/heikoaydt/Desktop/saas_env/testing'
password = "test"


class NodeTestCases(unittest.TestCase):
    # def setUp(self, n_nodes=2):
    #     port = 5010
    #
    #     self.nodes = []
    #     for i in range(0, n_nodes):
    #         address = ("127.0.0.1", port+i)
    #         node = Node(os.path.join(datastore_path, "node_{}".format(i)))
    #         node.initialise_identity(password)
    #         node.start_server(address)
    #         self.nodes.append(node)
    #
    # def tearDown(self):
    #     for i in range(0, len(self.nodes)):
    #         self.nodes[i].stop_server()

    def test_node_creation_and_initialisation(self):
        node = Node('test_node', datastore_path)

        # identity hasn't been initialised yet, so no key yet
        assert not node.key

        # server hasn't started yet, so no server socket
        assert not node.server_socket

        # initialise the identity, afterwards we should have a key, iid and short_iid
        node.initialise_identity(password)
        assert node.key
        assert node.key.iid
        assert node.key.short_iid

        # start the node server
        node.start_server(('127.0.0.1', 5000))
        assert node.server_socket

        time.sleep(5)
        node.stop_server()
        assert not node.server_socket

    def test_node_invalid_message(self):
        node0 = Node('node0', os.path.join(datastore_path, 'node0'))
        node0.initialise_identity(password)

        node1 = Node('node1', os.path.join(datastore_path, 'node1'))
        node1.initialise_identity(password)

        # start the node server
        address0 = ('127.0.0.1', 5000)
        node0.start_server(address0)
        assert node0.server_socket

        # establish a connection and send a malformed message
        peer, messenger = SecureMessenger.connect_to_peer(address0, node1)
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
        peer, messenger = SecureMessenger.connect_to_peer(address0, node1)
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
        node0 = Node('node0', os.path.join(datastore_path, 'node0'))
        node0.initialise_identity(password)

        node1 = Node('node1', os.path.join(datastore_path, 'node1'))
        node1.initialise_identity(password)

        # start the node server
        address0 = ('127.0.0.1', 5000)
        node0.start_server(address0)
        assert node0.server_socket

        # try to establish a connection to node0 but use the wrong port
        peer, messenger = SecureMessenger.connect_to_peer(('127.0.0.1', 5001), node1)
        assert not peer
        assert not messenger

        node0.stop_server()
        assert not node0.server_socket


if __name__ == '__main__':
    unittest.main()
