import unittest
import logging
import time

from saas.dor.blueprint import DORProxy
from saas.nodedb.blueprint import NodeDBProxy
from saas.nodedb.exceptions import DataObjectNotFoundError
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

        self.node = self.get_node('node', enable_rest=True)
        self.db = NodeDBProxy(self.node.rest.address())
        self.dor = DORProxy(self.node.rest.address())

        # create extra keystores and make them known to the node
        self.extras = self.create_keystores(2)
        for extra in self.extras:
            self.db.update_identity(extra.identity)

    def tearDown(self):
        self.cleanup()

    def test_node_self_awareness(self):
        identities = self.node.db.get_all_identities()
        assert(len(identities) == 1 + len(self.extras))
        assert(identities[self.node.identity().id].name == 'node')

        network = self.node.db.get_network()
        assert(len(network) == 1)
        assert(network[0]['iid'] == self.node.identity().id)

    def test_add_update_remove_tags(self):
        try:
            self.node.db.get_tags('invalid-object-id')
            assert False
        except DataObjectNotFoundError:
            assert True

        # add dummy data object
        owner = self.node.identity()
        obj_id0, _ = self.dor.add_data_object(self.generate_random_file('data000', 1024), owner,
                                              False, False, 'type', 'format', owner.name)
        obj_id1, _ = self.dor.add_data_object(self.generate_random_file('data000', 1024), owner,
                                              False, False, 'type', 'format', owner.name)

        tags = self.node.db.get_tags(obj_id0)
        assert(len(tags) == 0)

        self.node.db.update_tags(obj_id0, [
            {'key': 'k0', 'value': 'v0'}
        ])

        tags = self.node.db.get_tags(obj_id0)
        assert(len(tags) == 1)
        assert('k0' in tags)

        self.node.db.update_tags(obj_id0, [
            {'key': 'k1', 'value': 'v1'},
            {'key': 'k2', 'value': 'v2'}
        ])

        tags = self.node.db.get_tags(obj_id0)
        assert(len(tags) == 3)

        self.node.db.update_tags(obj_id0, [
            {'key': 'k0', 'value': '999'}
        ])

        tags = self.node.db.get_tags(obj_id0)
        assert(len(tags) == 3)
        assert(tags['k0'] == '999')

        self.node.db.remove_tags(obj_id0, ['k3'])
        tags = self.node.db.get_tags(obj_id0)
        assert(len(tags) == 3)

        self.node.db.remove_tags(obj_id1, ['k2'])
        tags = self.node.db.get_tags(obj_id0)
        assert(len(tags) == 3)

        self.node.db.remove_tags(obj_id0, ['k2'])
        tags = self.node.db.get_tags(obj_id0)
        assert(len(tags) == 2)

        self.node.db.remove_tags(obj_id0, ['k0', 'k1'])
        tags = self.node.db.get_tags(obj_id0)
        assert(len(tags) == 0)

    def test_grant_revoke_permissions(self):
        # add dummy data object
        owner = self.node.identity()
        obj_id, _ = self.dor.add_data_object(self.generate_random_file('data000', 1024), owner,
                                             False, False, 'type', 'format', owner.name)

        result = self.node.db.get_access_list(obj_id)
        assert(len(result) == 1)
        assert(owner.id in result)

        result = self.node.db.has_access(obj_id, self.extras[0].identity)
        assert(not result)

        result = self.node.db.has_access(obj_id, self.extras[1].identity)
        assert(not result)

        self.node.db.grant_access(obj_id, self.extras[0].identity)

        result = self.node.db.get_access_list(obj_id)
        assert(len(result) == 2)
        assert(owner.id in result)
        assert(self.extras[0].identity.id in result)

        self.node.db.revoke_access(obj_id, self.extras[1].identity)

        result = self.node.db.get_access_list(obj_id)
        assert(len(result) == 2)
        assert(owner.id in result)
        assert(self.extras[0].identity.id in result)

        self.node.db.revoke_access(obj_id, self.extras[0].identity)

        result = self.node.db.get_access_list(obj_id)
        assert(len(result) == 1)
        assert(owner.id in result)

    def test_update_identity(self):
        # check identities known to nodes (they should all know of each other)
        nodes = self.create_nodes(3, perform_join=True)
        for node in nodes:
            ids = node.db.get_all_identities()
            print(ids)
            assert(len(ids) == 3)

        # get the starting nonce
        node0_id = nodes[0].identity().id
        nonce0_by0_before = nodes[0].db.get_identity(node0_id).nonce
        nonce0_by1_before = nodes[1].db.get_identity(node0_id).nonce
        nonce0_by2_before = nodes[2].db.get_identity(node0_id).nonce

        # update id of node0 but don't propagate
        nodes[0].update_identity(name='bob', propagate=False)
        time.sleep(1)

        nonce0_by0_after = nodes[0].db.get_identity(node0_id).nonce
        nonce0_by1_after = nodes[1].db.get_identity(node0_id).nonce
        nonce0_by2_after = nodes[2].db.get_identity(node0_id).nonce
        assert(nonce0_by0_after == nonce0_by0_before + 1)
        assert(nonce0_by1_before == nonce0_by1_after)
        assert(nonce0_by2_before == nonce0_by2_after)

        # update id of node0
        nodes[0].update_identity(name='jane', propagate=True)
        time.sleep(1)

        nonce0_by0_after = nodes[0].db.get_identity(node0_id).nonce
        nonce0_by1_after = nodes[1].db.get_identity(node0_id).nonce
        nonce0_by2_after = nodes[2].db.get_identity(node0_id).nonce
        assert(nonce0_by0_after == nonce0_by0_before + 2)
        assert(nonce0_by1_after == nonce0_by1_before + 2)
        assert(nonce0_by2_after == nonce0_by2_before + 2)

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
            nodes[i].db.update_identity(extras[i].identity.serialise())

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
            nodes[i].db.update_identity(extras[i].identity.serialise(), propagate=False)

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

        iid0 = nodes[0].identity().id

        proxy0 = NodeDBProxy(nodes[0].rest.address())
        proxy1 = NodeDBProxy(nodes[1].rest.address())
        proxy2 = NodeDBProxy(nodes[2].rest.address())

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

        identity = proxy0.get_identity(iid0)
        assert(identity.id == iid0)

        identity = nodes[0].update_identity(name='updated_name')
        proxy0.update_identity(identity)

        result = proxy0.get_identities()
        print(result)
        assert(result[iid0].name == 'updated_name')

        result = proxy1.get_identities()
        print(result)
        assert(result[iid0].name == 'updated_name')

        result = proxy2.get_identities()
        print(result)
        assert(result[iid0].name == 'updated_name')

    def test_service_availability(self):
        node_s = self.get_node('storage_node', use_dor=True, use_rti=False, enable_rest=True)
        node_e = self.get_node('execution_node', use_dor=False, use_rti=True, enable_rest=True)

        proxy_s = NodeDBProxy(node_s.rest.address())
        proxy_e = NodeDBProxy(node_e.rest.address())

        result_s = proxy_s.get_node()
        print(result_s)
        assert (result_s['dor_service'] is True)
        assert (result_s['rti_service'] is False)

        result_e = proxy_e.get_node()
        print(result_e)
        assert (result_e['dor_service'] is False)
        assert (result_e['rti_service'] is True)


if __name__ == '__main__':
    unittest.main()
