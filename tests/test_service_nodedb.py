import unittest
import logging
import time

from saas.cryptography.eckeypair import ECKeyPair
from saas.keystore.keystore import Identity
from saas.nodedb.blueprint import NodeDBProxy
from tests.base_testcase import TestCaseBase

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class NodeDBServiceTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

    def tearDown(self):
        self.cleanup()

    def test_node_self_awareness(self):
        node = self.get_node('node')

        identities = node.db.get_all_identities()
        assert(len(identities) == 1)
        assert(identities[node.identity().id()].name() == 'node')

        network = node.db.get_network()
        assert(len(network) == 1)
        assert(network[0].iid == node.identity().id())

    def test_add_update_remove_tags(self):
        node = self.get_node('node')

        tags = node.db.get_tags('aaa')
        assert(len(tags) == 0)

        node.db.update_tags('aaa', [
            {'key': 'k0', 'value': 'v0'}
        ])

        tags = node.db.get_tags('aaa')
        assert(len(tags) == 1)
        assert('k0' in tags)

        node.db.update_tags('aaa', [
            {'key': 'k1', 'value': 'v1'},
            {'key': 'k2', 'value': 'v2'}
        ])

        tags = node.db.get_tags('aaa')
        assert(len(tags) == 3)

        node.db.update_tags('aaa', [
            {'key': 'k0', 'value': '999'}
        ])

        tags = node.db.get_tags('aaa')
        assert(len(tags) == 3)
        assert(tags['k0'] == '999')

        node.db.remove_tags('aaa', ['k3'])
        tags = node.db.get_tags('aaa')
        assert(len(tags) == 3)

        node.db.remove_tags('bbb', ['k2'])
        tags = node.db.get_tags('aaa')
        assert(len(tags) == 3)

        node.db.remove_tags('aaa', ['k2'])
        tags = node.db.get_tags('aaa')
        assert(len(tags) == 2)

        node.db.remove_tags('aaa', ['k0', 'k1'])
        tags = node.db.get_tags('aaa')
        assert(len(tags) == 0)

    def test_find_data_objects(self):
        node = self.get_node('node')

        node.db.update_tags('aaa', [
            {'key': 'k0', 'value': 'v00'},
            {'key': 'k1', 'value': 'v1'}
        ])

        node.db.update_tags('bbb', [
            {'key': 'k0', 'value': 'v01'},
            {'key': 'k2', 'value': 'v2'}
        ])

        obj_ids = node.db.find_data_objects('k0')
        assert(len(obj_ids) == 2)
        assert('aaa' in obj_ids)
        assert('bbb' in obj_ids)

        obj_ids = node.db.find_data_objects('k1')
        assert(len(obj_ids) == 1)
        assert('aaa' in obj_ids)

        obj_ids = node.db.find_data_objects('k2')
        assert(len(obj_ids) == 1)
        assert('bbb' in obj_ids)

        obj_ids = node.db.find_data_objects('k3')
        assert(len(obj_ids) == 0)

        obj_ids = node.db.find_data_objects('k0', 'v00')
        assert(len(obj_ids) == 1)
        assert('aaa' in obj_ids)

        obj_ids = node.db.find_data_objects('k0', 'v02')
        assert(len(obj_ids) == 0)

        obj_ids = node.db.find_data_objects('k0', 'v0%')
        assert(len(obj_ids) == 2)

        obj_ids = node.db.find_data_objects(value_criterion='v1')
        assert(len(obj_ids) == 1)
        assert('aaa' in obj_ids)

    def test_grant_revoke_permissions(self):
        node = self.get_node('node')
        keystores = self.create_keystores(2)

        result = node.db.get_access_list('aaa')
        assert(len(result) == 0)

        result = node.db.has_access('aaa', keystores[0].identity())
        assert(not result)

        result = node.db.has_access('aaa', keystores[1].identity())
        assert(not result)

        node.db.grant_access('aaa', keystores[0].identity(), 'permission1')

        result = node.db.get_access_list('aaa')
        assert(len(result) == 1)
        assert(keystores[0].identity().id() in result)

        node.db.revoke_access('aaa', keystores[1].identity())

        result = node.db.get_access_list('aaa')
        assert(len(result) == 1)
        assert(keystores[0].identity().id() in result)

        node.db.revoke_access('aaa', keystores[0].identity())

        result = node.db.get_access_list('aaa')
        assert(len(result) == 0)

    def test_update_identity(self):
        nodes = self.create_nodes(3)

        # check identities known to nodes (they should all know of each other)
        for node in nodes:
            ids = node.db.get_all_identities()
            print(ids)
            assert(len(ids) == 3)

        # update id of node0 but don't propagate
        nodes[0].update_identity(name='bob', propagate=False)
        time.sleep(1)

        node0_id = nodes[0].identity().id()
        identity0_by0 = nodes[0].db.get_identity(node0_id)
        identity0_by1 = nodes[1].db.get_identity(node0_id)
        identity0_by2 = nodes[2].db.get_identity(node0_id)

        assert(identity0_by0.nonce() == 2)
        assert(identity0_by1.nonce() == 1)
        assert(identity0_by2.nonce() == 1)

        # update id of node0
        nodes[0].update_identity(name='jane', propagate=True)
        time.sleep(1)

        node0_id = nodes[0].identity().id()
        identity0_by0 = nodes[0].db.get_identity(node0_id)
        identity0_by1 = nodes[1].db.get_identity(node0_id)
        identity0_by2 = nodes[2].db.get_identity(node0_id)

        assert(identity0_by0.nonce() == 3)
        assert(identity0_by1.nonce() == 3)
        assert(identity0_by2.nonce() == 3)

    def test_snapshot(self):
        # create nodes but don't form network
        nodes = self.create_nodes(3, perform_join=False)

        # each node should know about 1 identity (its own)
        for node in nodes:
            ids = node.db.get_all_identities()
            assert(len(ids) == 1)

        # feed each node with an extra identity
        extras = self.create_keystores(len(nodes))
        for i in range(len(nodes)):
            signature = extras[i].update()
            nodes[i].db.update_identity(extras[i].identity().serialise(), signature)

        # each node should know about 2 identities now
        for node in nodes:
            ids = node.db.get_all_identities()
            assert(len(ids) == 2)

        # send snapshot from node 0 to node 1
        nodes[0].db.protocol.send_snapshot(nodes[1].p2p.address())
        time.sleep(2)

        # send snapshot from node 1 to node 2
        nodes[1].db.protocol.send_snapshot(nodes[2].p2p.address())
        time.sleep(2)

        # node 0 should know about 2 identities now
        ids = nodes[0].db.get_all_identities()
        assert (len(ids) == 2)

        # node 1 should know about 4 identities now
        ids = nodes[1].db.get_all_identities()
        assert (len(ids) == 4)

        # node 2 should know about 6 identities now
        ids = nodes[2].db.get_all_identities()
        assert (len(ids) == 6)

    def test_join_protocol(self):
        nodes = self.create_nodes(3, perform_join=True)

        # each node should know about 3 identities
        for node in nodes:
            ids = node.db.get_all_identities()
            assert(len(ids) == 3)

        # feed each node with an extra identity
        extras = self.create_keystores(len(nodes))
        for i in range(len(nodes)):
            signature = extras[i].update()
            nodes[i].db.update_identity(extras[i].identity().serialise(), signature, propagate=False)

        # each node should know about 4 identities now
        for node in nodes:
            ids = node.db.get_all_identities()
            assert(len(ids) == 4)

        # create more nodes and manually join them with the existing nodes
        nodes2 = self.create_nodes(len(nodes), offset=len(nodes), perform_join=False)
        for i in range(len(nodes2)):
            nodes2[i].join_network(nodes[i].p2p.address())

        time.sleep(2)

        # each node should know about 9 identities (len(nodes) + len(extras) + len(nodes2))
        all_nodes = nodes + nodes2
        for node in all_nodes:
            ids = node.db.get_all_identities()
            assert(len(ids) == len(nodes) + len(extras) + len(nodes2))

    def test_proxy(self):
        nodes = self.create_nodes(3, perform_join=True, enable_rest=True)
        time.sleep(2)

        iid0 = nodes[0].identity().id()

        proxy0 = NodeDBProxy(nodes[0].rest.address(), nodes[0])
        proxy1 = NodeDBProxy(nodes[1].rest.address(), nodes[0])
        proxy2 = NodeDBProxy(nodes[2].rest.address(), nodes[0])

        result = proxy0.get_node()
        print(result)
        assert(result is not None)
        assert(result['iid'] == iid0)

        result = proxy0.get_network()
        print(result)
        assert(result is not None)
        assert(len(result) == 3)

        result = proxy0.get_identities()
        print(result)
        assert(result is not None)
        assert(len(result) == 3)

        result = proxy0.get_identity(iid0)
        print(result)
        identity = Identity.deserialise(result)
        assert(identity.id() == iid0)
        assert(identity.nonce() == 1)

        identity, signature = nodes[0].update_identity(name='updated_name')
        proxy0.update_identity(identity, signature)

        result = proxy0.get_identities()
        print(result)
        assert(result[iid0]['name'] == 'updated_name')

        result = proxy1.get_identities()
        print(result)
        assert(result[iid0]['name'] == 'updated_name')

        result = proxy2.get_identities()
        print(result)
        assert(result[iid0]['name'] == 'updated_name')


if __name__ == '__main__':
    unittest.main()
