import unittest
import logging
import time

from saas.registry.blueprint import RegistryProxy
from tests.base_testcase import TestCaseBase

from saas.registry.protocol import RegistryP2PProtocol

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class RegistryServiceTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

    def tearDown(self):
        self.cleanup()

    def test_update1(self):
        node0 = self.get_node(f"node_0")
        r0 = node0.registry.get()
        print(r0)
        assert(len(r0) == 1)
        assert(node0.id() in r0)

        node1 = self.get_node(f"node_1")
        r1 = node1.registry.get()
        print(r1)
        assert(len(r1) == 1)
        assert(node1.id() in r1)

        # make node 0 aware of node 1
        node0.registry.update(
            node1.id(),
            node1.name(),
            node1.p2p.address(),
            None
        )

        r0 = node0.registry.get()
        print(r0)
        assert(len(r0) == 2)
        assert(node0.id() in r0)
        assert(node1.id() in r0)

        r1 = node1.registry.get()
        print(r1)
        assert(len(r1) == 1)
        assert(node1.id() in r1)

    def test_update2(self):
        node = self.get_node(f"node")

        # empty registry: adding a new records should be successful
        assert node.registry.update('123', 'name1', ('127.0.0.1', 4000), ('127.0.0.1', 5000), ['a', 'b'], 100)
        assert node.registry.update('234', 'name2', ('127.0.0.1', 4000), ('127.0.0.1', 5000), ['a', 'b'], 100)

        # there should be three records in the registry now (2 + the record about the node itself)
        print(node.registry.get())
        assert node.registry.size() == 3

        # records already exists and timestamps are NOT more recent: updates should fail
        assert not node.registry.update('123', 'name1', ('127.0.0.1', 4000), ('127.0.0.1', 5000), ['a', 'b'], 100)
        assert not node.registry.update('123', 'name1', ('127.0.0.1', 4000), ('127.0.0.1', 5000), ['a', 'b'], 99)

        # records already exists and timestamps are more recent: update should succeed
        assert node.registry.update('123', 'name1', ('127.0.0.1', 4000), ('127.0.0.1', 5000), ['a', 'b', 'c'], 101)

        # the information of record '123' should be updated now
        record = node.registry.get('123')
        assert record
        assert all(item in record['processors'] for item in ['a', 'b', 'c'])

    def test_update_all(self):
        node = self.get_node(f"node")

        records_a = {
            '123': {
                'name': 'node1',
                'p2p_address': ('127.0.0.1', 4000),
                'rest_api_address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 100
            },
            '234': {
                'name': 'node2',
                'p2p_address': ('127.0.0.1', 4000),
                'rest_api_address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 99
            }
        }

        records_b = {
            '123': {
                'name': 'node1',
                'p2p_address': ('127.0.0.1', 4000),
                'rest_api_address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 99
            },
            '234': {
                'name': 'node2',
                'p2p_address': ('127.0.0.1', 4000),
                'rest_api_address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 98
            }
        }

        # empty registry: adding a new records should be successful for al items
        assert len(node.registry.update_all(records_a)) == 2

        # adding records that are LESS RECENT should fail
        assert len(node.registry.update_all(records_b)) == 0

    def test_touch(self):
        node = self.get_node(f"node")

        # empty registry: adding a new records should be successful
        assert node.registry.update('123', ('127.0.0.1', 4000), ('127.0.0.1', 5000), ['a', 'b'], 100)

        # touching an existing record should yield a timestamp
        t0 = node.registry.touch('123')
        assert t0 is not None

        # the last_seen timestamp on record should match t0
        record = node.registry.get('123')
        assert t0 == record['last_seen']

        # touching a non-existing record should yield None
        t1 = node.registry.touch('234')
        assert t1 is None

    def test_remove(self):
        node = self.get_node(f"node")

        records_a = {
            '123': {
                'name': 'node1',
                'p2p_address': ('127.0.0.1', 4000),
                'rest_api_address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 100
            },
            '234': {
                'name': 'node2',
                'p2p_address': ('127.0.0.1', 4000),
                'rest_api_address': ('127.0.0.1', 5000),
                'processors': ['a', 'b'],
                'last_seen': 99
            }
        }

        # empty registry: adding a new records should be successful for al items
        assert len(node.registry.update_all(records_a)) == 2

        # size of registry should be 2
        assert node.registry.size() == 3

        # remove a record that doesn't exist: the size should be 2
        removed = node.registry.remove(['222'])
        assert len(removed) == 0
        assert node.registry.size() == 3

        # remove a record that does exist: the size should be 1
        removed = node.registry.remove(['123'])
        assert len(removed) == 1
        assert '123' in removed
        assert node.registry.size() == 2

    def test_ping_pong(self):
        nodes = self.create_nodes(2)

        # nodes ignore ping messages from nodes they don't know about, so we need to make sure
        # the nodes know of each other first.
        # send a join message to node0
        protocol = RegistryP2PProtocol(nodes[1])
        protocol.send_join(nodes[0].p2p.address())
        time.sleep(1)

        # use the registry messenger protocol to send a ping message
        protocol = RegistryP2PProtocol(nodes[0])
        protocol.send_ping(nodes[1].id())

    def test_join(self):
        n = 4
        nodes = self.create_nodes(n)

        for i in range(0, len(nodes)):
            records = nodes[i].registry.get()
            print(records)

            logger.info(f"node[{i}] records: {records}")
            assert(len(records) == n)

            for node in nodes:
                if node.id() not in records:
                    logger.error(f"Node {node.id()} not found in records of node {nodes[i].id()}")
                    assert False

    def test_leave(self):
        nodes = self.create_nodes(2)

        # nodes 0 and 1 should now know of each other
        records0 = nodes[0].registry.get()
        assert (len(records0) == 2)

        records1 = nodes[0].registry.get()
        assert (len(records1) == 2)

        # now do a leave
        protocol = RegistryP2PProtocol(nodes[1])
        protocol.broadcast_leave()
        time.sleep(2)

        # nodes 0 should have removed the record of node 1
        records0 = nodes[0].registry.get()
        assert (len(records0) == 1)

    def test_proxy(self):
        node = self.get_node('node', enable_rest=True)
        proxy = RegistryProxy(node.rest.address(), node.identity())

        result = proxy.get_node_info()
        print(result)
        assert(result is not None)
        assert(result['iid'] == node.id())

        result = proxy.get_registry_contents()
        print(result)
        assert(result is not None)
        assert(node.id() in result)


if __name__ == '__main__':
    unittest.main()
