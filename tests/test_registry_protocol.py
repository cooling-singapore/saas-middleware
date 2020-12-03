import unittest
import logging
import os
import time

import saas.utilities.general_helpers as utilities

from saas.node import Node
from saas.registry.protocol import RegistryP2PProtocol

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class RegistryTestCases(unittest.TestCase):
    def setUp(self, n_nodes=4):
        datastore_path = '/Users/heikoaydt/Desktop/saas_env/testing'
        password = "password"
        port = 5010

        self.nodes = []
        for i in range(0, n_nodes):
            address = ("127.0.0.1", port+i)
            node = Node("node_{}".format(i), os.path.join(datastore_path, "node_{}".format(i)))
            node.initialise_identity(password)
            node.start_server(address)
            node.initialise_registry(address)
            self.nodes.append(node)

    def tearDown(self):
        for i in range(0, len(self.nodes)):
            self.nodes[i].stop_server()

    def test_ping_pong(self):
        # make node 0 aware of node 1
        self.nodes[0].registry.update(self.nodes[1].key.iid, self.nodes[1].name, self.nodes[1].server_address, [], utilities.get_timestamp_now())

        # use the registry messenger protocol to send a ping message
        protocol = RegistryP2PProtocol(self.nodes[0])
        protocol.send_ping(self.nodes[1].key.iid)

    def test_join(self):
        protocol = RegistryP2PProtocol(self.nodes[1])
        protocol.send_join(self.nodes[0].server_address)
        time.sleep(5)

        protocol = RegistryP2PProtocol(self.nodes[2])
        protocol.send_join(self.nodes[0].server_address)
        time.sleep(5)

        protocol = RegistryP2PProtocol(self.nodes[3])
        protocol.send_join(self.nodes[0].server_address)
        time.sleep(5)

        for i in range(0, len(self.nodes)):
            records = self.nodes[i].registry.get()

            logger.info("node[{}] records: {}".format(i, records))
            assert(len(records) == 4)

            for node in self.nodes:
                if node.key.iid not in records:
                    logger.error("Node {} not found in records of node {}".format(node.key.iid, self.nodes[i].key.iid))
                    assert False

    def test_leave(self):
        # first do a join
        protocol = RegistryP2PProtocol(self.nodes[1])
        protocol.send_join(self.nodes[0].server_address)
        time.sleep(5)

        # nodes 0 and 1 should now know of each other
        records0 = self.nodes[0].registry.get()
        assert (len(records0) == 2)

        records1 = self.nodes[0].registry.get()
        assert (len(records1) == 2)

        # now do a leave
        protocol.broadcast_leave()
        time.sleep(5)

        # nodes 0 should have removed the record of node 1
        records0 = self.nodes[0].registry.get()
        assert (len(records0) == 1)


if __name__ == '__main__':
    unittest.main()
