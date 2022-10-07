import os
import shutil
import unittest
import logging
import time

from saas.core.helpers import get_timestamp_now
from saas.core.keystore import Keystore
from saas.core.logging import Logging
from saas.node import Node
from saas.nodedb.proxy import NodeDBProxy
from tests.base_testcase import TestCaseBase, PortMaster

Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


class NodeDBServiceTestCase(unittest.TestCase, TestCaseBase):
    _wd_path = os.path.join(os.environ['HOME'], 'testing', str(get_timestamp_now()))
    _node = None
    _db = None
    _extras = None

    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    @classmethod
    def tearDownClass(cls):
        if cls._node is not None:
            shutil.rmtree(cls._wd_path, ignore_errors=True)
            cls._node.shutdown(leave_network=False)

    def setUp(self):
        self.initialise()

        if NodeDBServiceTestCase._node is None:
            NodeDBServiceTestCase._node = self.get_node('node', enable_rest=True, keep_track=False,
                                                        wd_path=NodeDBServiceTestCase._wd_path)
            NodeDBServiceTestCase._db = NodeDBProxy(NodeDBServiceTestCase._node.rest.address())

            NodeDBServiceTestCase._extras = self.create_keystores(2)
            for keystore in NodeDBServiceTestCase._extras:
                NodeDBServiceTestCase._db.update_identity(keystore.identity)
            time.sleep(1)

    def tearDown(self):
        self.cleanup()

    def test_rest_get_node(self):
        node = self._db.get_node()
        print(node)
        assert(node is not None)

    def test_rest_get_network(self):
        network = self._db.get_network()
        print(network)
        assert(network is not None)
        assert(len(network) == 1)

    def test_rest_get_identities(self):
        identities = self._db.get_identities()
        print(identities)
        assert(identities is not None)
        assert(len(identities) == 1 + len(self._extras))

    def test_rest_get_identity_valid(self):
        valid_iid = self._node.identity.id

        identity = self._db.get_identity(valid_iid)
        print(identity)
        assert(identity is not None)
        assert(identity.id == self._node.identity.id)

    def test_rest_get_identity_invalid(self):
        invalid_iid = 'f00baa'

        identity = self._db.get_identity(invalid_iid)
        assert(identity is None)

    def test_rest_update_identity_existing(self):
        new_name = self._node.identity.name + "2"

        keystore: Keystore = self._node.keystore
        keystore.update_profile(new_name)

        result = self._db.update_identity(keystore.identity)
        print(result)
        assert(result is not None)
        assert(result.name == new_name)

    def test_rest_update_identity_extra(self):
        identities0 = self._db.get_identities()

        extra = self.create_keystores(1)[0]
        self._db.update_identity(extra.identity)

        identities1 = self._db.get_identities()
        assert(len(identities1) == len(identities0) + 1)

    def test_node_self_awareness(self):
        identities = self._node.db.get_identities()
        assert(len(identities) == 1 + len(self._extras))
        identities = {i.id: i for i in identities}
        assert(identities[self._node.identity.id].name == 'node')

        network = self._node.db.get_network()
        assert(len(network) == 1)
        assert(network[0].identity.id == self._node.identity.id)

    def test_different_address(self):
        p2p_address = PortMaster.generate_p2p_address(self.host)

        # manually create a node on a certain address and make it known to the self.node
        node0 = Node(self._extras[0], os.path.join(self.wd_path, 'node0'))
        node0.startup(p2p_address, enable_dor=False, enable_rti=False, rest_address=None)
        node0.join_network(self._node.p2p.address())

        # the self.node should know of 2 nodes now
        network = self._db.get_network()
        network = [item.identity.id for item in network]
        assert(len(network) == 2)
        assert(self._node.identity.id in network)
        assert(node0.identity.id in network)

        # shutdown the first node silently (i.e., not leaving the network) - this emulates what happens
        # when a node suddenly crashes for example.
        node0.shutdown(leave_network=False)

        # the self.node should still know 2 nodes
        network = self._db.get_network()
        network = [item.identity.id for item in network]
        assert(len(network) == 2)
        assert(self._node.identity.id in network)
        assert(node0.identity.id in network)

        # manually create a second node, using the same address but a different keystore
        node1 = Node(self._extras[1], os.path.join(self.wd_path, 'node1'))
        node1.startup(p2p_address, enable_dor=False, enable_rti=False, rest_address=None)

        # at this point node1 should only know about itself
        network = node1.db.get_network()
        network = [item.identity.id for item in network]
        assert(len(network) == 1)
        assert(node1.identity.id in network)

        # perform the join
        node1.join_network(self._node.p2p.address())

        # the self.node should now still only know of 2 nodes now (the first node should be replaced)
        network = self._db.get_network()
        network = [item.identity.id for item in network]
        assert(len(network) == 2)
        assert(self._node.identity.id in network)
        assert(node1.identity.id in network)

        node0.shutdown()
        node1.shutdown()

    def test_join_leave_protocol(self):
        nodes = self.create_nodes(3, perform_join=False)

        # each node should know about 1 identity: its own
        for node in nodes:
            identities = node.db.get_identities()
            assert(len(identities) == 1)
            assert(identities[0].id == node.identity.id)

        # tell node 1 to join the network with node 0
        nodes[1].join_network(nodes[0].p2p.address())

        # nodes 0 and 1 should know about each other and node 2 only about itself
        for node in nodes:
            identities = node.db.get_identities()
            if node == nodes[0] or node == nodes[1]:
                assert(len(identities) == 2)
                assert(identities[0].id == nodes[0].identity.id or nodes[1].identity.id)
                assert(identities[1].id == nodes[0].identity.id or nodes[1].identity.id)

            else:
                assert(len(identities) == 1)
                assert(identities[0].id == nodes[2].identity.id)

        # tell node 2 to join the network with node 0
        nodes[2].join_network(nodes[0].p2p.address())

        # all nodes should now know about each other
        for node in nodes:
            identities = node.db.get_identities()
            assert(len(identities) == 3)

            network = node.db.get_network()
            assert(len(network) == 3)

        # tell node 2 to leave the network
        nodes[2].leave_network()

        # all nodes should still know about each other's identities BUT the network for nodes 0 and 1 is now only
        # of size 2 while node 2 now only knows about itself.
        for node in nodes:
            identities = node.db.get_identities()
            assert(len(identities) == 3)

            network = node.db.get_network()
            if node == nodes[0] or node == nodes[1]:
                assert(len(network) == 2)

            else:
                assert(len(network) == 1)
                assert(network[0].identity.id == node.identity.id)

    def test_update_identity(self):
        # all nodes should now know about each other
        nodes = self.create_nodes(3, perform_join=True)
        for node in nodes:
            identities = node.db.get_identities()
            assert(len(identities) == 3)

            network = node.db.get_network()
            assert(len(network) == 3)

        # get the starting nonce
        node0_id = nodes[0].identity.id
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

    def test_proxy(self):
        nodes = self.create_nodes(3, perform_join=True, enable_rest=True)
        time.sleep(2)

        iid0 = nodes[0].identity.id

        proxy0 = NodeDBProxy(nodes[0].rest.address())
        proxy1 = NodeDBProxy(nodes[1].rest.address())
        proxy2 = NodeDBProxy(nodes[2].rest.address())

        result = proxy0.get_node()
        print(result)
        assert(result is not None)
        assert(result.identity.id == iid0)

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
        assert (result_s.dor_service is True)
        assert (result_s.rti_service is False)

        result_e = proxy_e.get_node()
        print(result_e)
        assert (result_e.dor_service is False)
        assert (result_e.rti_service is True)


if __name__ == '__main__':
    unittest.main()
