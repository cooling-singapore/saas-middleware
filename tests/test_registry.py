import unittest
import logging
import os
import time

import saas.utilities.general_helpers as utilities

from tests.testing_environment import TestingEnvironment
from saas.node import Node
from saas.registry.protocol import RegistryP2PProtocol
from saas.registry.registry import Registry

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)
env = TestingEnvironment.get_instance('/Users/heikoaydt/Desktop/saas_env/testing-config.json')
n_nodes = 4


class RegistryTestCases(unittest.TestCase):
    def setUp(self):
        env.prepare_working_directory()

        self.nodes = []
        for i in range(0, n_nodes):
            name = "node_{}".format(i)
            datastore_path = os.path.join(env.wd_path, name)

            logger.info("creating node '{}'".format(name))
            node = Node(name, datastore_path)
            node.initialise_identity(env.password)
            node.start_server((env.p2p_host, env.p2p_port + i))

            # important note: in the following, we indicate the node we just created as the boot node. which means
            # the N nodes we create in this loop do not know of each other at this point. this is intentional here
            # for the purpose of testing the code. in a real application you would want to use the address of a real
            # boot node.
            node.initialise_registry((env.p2p_host, env.p2p_port + i))

            self.nodes.append(node)

    def tearDown(self):
        for node in self.nodes:
            logger.info("stopping node '{}'".format(node.name))
            node.stop_server()

    def test_update(self):
        registry = Registry(None)

        # empty registry: adding a new records should be successful
        assert registry.update('123', 'name1', ('127.0.0.1', 5000), ['a', 'b'], 100)
        assert registry.update('234', 'name2', ('127.0.0.1', 5000), ['a', 'b'], 100)

        # there should be two records in the registry now
        assert registry.size() == 2

        # records already exists and timestamps are NOT more recent: updates should fail
        assert not registry.update('123', 'name1', ('127.0.0.1', 5000), ['a', 'b'], 100)
        assert not registry.update('123', 'name1', ('127.0.0.1', 5000), ['a', 'b'], 99)

        # records already exists and timestamps are more recent: update should succeed
        assert registry.update('123', 'name1', ('127.0.0.1', 5000), ['a', 'b', 'c'], 101)

        # the information of record '123' should be updated now
        record = registry.get('123')
        assert record
        assert all(item in record['processors'] for item in ['a', 'b', 'c'])

    def test_update_all(self):
        registry = Registry(None)

        records_a = {
            '123': {
                'name': 'node1',
                'address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 100
            },
            '234': {
                'name': 'node2',
                'address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 99
            }
        }

        records_b = {
            '123': {
                'name': 'node1',
                'address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 99
            },
            '234': {
                'name': 'node2',
                'address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 98
            }
        }

        # empty registry: adding a new records should be successful for al items
        assert len(registry.update_all(records_a)) == 2

        # adding records that are LESS RECENT should fail
        assert len(registry.update_all(records_b)) == 0

    def test_touch(self):
        registry = Registry(None)

        # empty registry: adding a new records should be successful
        assert registry.update('123', ('127.0.0.1', 5000), ['a', 'b'], 100)

        # touching an existing record should yield a timestamp
        t0 = registry.touch('123')
        assert t0 is not None

        # the last_seen timestamp on record should match t0
        record = registry.get('123')
        assert t0 == record['last_seen']

        # touching a non-existing record should yield None
        t1 = registry.touch('234')
        assert t1 is None

    def test_remove(self):
        registry = Registry(None)

        records_a = {
            '123': {
                'name': 'node1',
                'address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 100
            },
            '234': {
                'name': 'node2',
                'address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 99
            }
        }

        # empty registry: adding a new records should be successful for al items
        assert len(registry.update_all(records_a)) == 2

        # size of registry should be 2
        assert registry.size() == 2

        # remove a record that doesn't exist: the size should be 2
        removed = registry.remove(['222'])
        assert len(removed) == 0
        assert registry.size() == 2

        # remove a record that does exist: the size should be 1
        removed = registry.remove(['123'])
        assert len(removed) == 1
        assert '123' in removed
        assert registry.size() == 1

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
