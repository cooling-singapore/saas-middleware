import os
import shutil
import unittest
import logging
import time

from saascore.api.sdk.exceptions import UnsuccessfulRequestError
from saascore.api.sdk.proxies import NodeDBProxy
from saascore.helpers import get_timestamp_now
from saascore.keystore.identity import Identity
from saascore.keystore.keystore import Keystore
from saascore.log import Logging

from saas.dor.schemas import Tag
from saas.node import Node
from saas.nodedb.exceptions import DataObjectNotFoundError
from saas.nodedb.service import NodeDBService
from tests.base_testcase import TestCaseBase, PortMaster

Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


class NodeDBRESTTestCase(unittest.TestCase, TestCaseBase):
    _wd_path = os.path.join(os.environ['HOME'], 'testing', str(get_timestamp_now()))
    _node = None
    _db = None

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

        if NodeDBRESTTestCase._node is None:
            NodeDBRESTTestCase._node = self.get_node('node', enable_rest=True, keep_track=False,
                                                     wd_path=NodeDBRESTTestCase._wd_path)
            NodeDBRESTTestCase._db = NodeDBProxy(NodeDBRESTTestCase._node.rest.address())
            time.sleep(1)

    def tearDown(self):
        self.cleanup()

    def test_rest_get_node(self):
        result = self._db.get_node()
        print(result)
        assert(result is not None)

    def test_rest_get_network(self):
        result = self._db.get_network()
        print(result)
        assert(result is not None)

    def test_rest_get_identities(self):
        result = self._db.get_identities()
        print(result)
        assert(result is not None)
        assert(len(result) == 1)

    def test_rest_update_identity(self):
        new_name = self._node.identity.name + "2"

        keystore: Keystore = self._node.keystore
        keystore.update_profile(new_name)

        result = self._db.update_identity(keystore.identity)
        print(result)
        assert(result is not None)
        assert(result.name == new_name)

    def test_rest_get_identity_valid(self):
        valid_iid = self._node.identity.id

        result = self._db.get_identity(valid_iid)
        print(result)
        assert(result is not None)

    def test_rest_get_identity_invalid(self):
        invalid_iid = 'f00baa'

        result = self._db.get_identity(invalid_iid)
        print(result)
        assert(result is None)

    def test_rest_get_provenance_invalid(self):
        invalid_obj_id = 'f00baa'

        try:
            self._db.get_provenance(invalid_obj_id)
            assert False

        except UnsuccessfulRequestError as e:
            assert('Data object not found' in e.reason)
            assert(e.details['obj_id'] == invalid_obj_id)


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

    def test_update_remove_tags(self):
        meta0 = self._node.db.add_data_object('foobaa0', None, 'data_type', 'data_format', 'created_by', None,
                                              self._node.identity, False, False)
        obj_id0 = meta0['obj_id']
        assert(len(meta0['tags']) == 0)

        meta1 = self._node.db.add_data_object('foobaa1', None, 'data_type', 'data_format', 'created_by', None,
                                              self._node.identity, False, False)
        obj_id1 = meta1['obj_id']
        assert(len(meta1['tags']) == 0)

        self._node.db.update_tags(obj_id0, [
            Tag(key='k0', value='v0')
        ])
        meta0 = self._node.db.get_object_by_id(obj_id0)
        assert(len(meta0['tags']) == 1)
        tags = {i['key']: i['value'] for i in meta0['tags']}
        assert('k0' in tags)

        self._node.db.update_tags(obj_id0, [
            Tag(key='k1', value='v1'),
            Tag(key='k2', value='v2')
        ])
        meta0 = self._node.db.get_object_by_id(obj_id0)
        assert(len(meta0['tags']) == 3)

        self._node.db.update_tags(obj_id0, [
            Tag(key='k0', value='999')
        ])
        meta0 = self._node.db.get_object_by_id(obj_id0)
        assert(len(meta0['tags']) == 3)
        tags = {i['key']: i['value'] for i in meta0['tags']}
        assert(tags['k0'] == '999')

        self._node.db.remove_tags(obj_id0, ['k3'])
        meta0 = self._node.db.get_object_by_id(obj_id0)
        assert(len(meta0['tags']) == 3)

        self._node.db.remove_tags(obj_id1, ['k2'])
        meta0 = self._node.db.get_object_by_id(obj_id0)
        assert(len(meta0['tags']) == 3)

        self._node.db.remove_tags(obj_id0, ['k2'])
        meta0 = self._node.db.get_object_by_id(obj_id0)
        assert(len(meta0['tags']) == 2)

        self._node.db.remove_tags(obj_id0, ['k0', 'k1'])
        meta0 = self._node.db.get_object_by_id(obj_id0)
        assert(len(meta0['tags']) == 0)

    def test_get_statistics(self):
        result = self._node.db.get_statistics()
        assert(result is not None)

    def test_find_data_objects(self):
        pass

    def test_has_grant_revoke_access(self):
        db: NodeDBService = self._node.db
        owner: Identity = self._node.identity

        meta = db.add_data_object('foobaa2', None, 'data_type', 'data_format', 'created_by', None, owner, False, False)
        obj_id = meta['obj_id']

        assert(len(meta['access']) == 1)
        assert(owner.id in meta['access'])

        assert db.has_access(obj_id, owner)
        assert not db.has_access(obj_id, self._extras[0].identity)
        assert not db.has_access(obj_id, self._extras[1].identity)

        db.grant_access(obj_id, self._extras[0].identity)
        meta = db.get_object_by_id(obj_id)
        assert(len(meta['access']) == 2)
        assert(owner.id in meta['access'])
        assert(self._extras[0].identity.id in meta['access'])

        db.revoke_access(obj_id, self._extras[1].identity)
        meta = db.get_object_by_id(obj_id)
        assert(len(meta['access']) == 2)
        assert(owner.id in meta['access'])
        assert(self._extras[0].identity.id in meta['access'])

        db.revoke_access(obj_id, self._extras[0].identity)
        meta = db.get_object_by_id(obj_id)
        assert(len(meta['access']) == 1)
        assert(owner.id in meta['access'])

    def test_add_get_remove_data_object(self):
        db: NodeDBService = self._node.db
        owner: Identity = self._node.identity
        c_hash = 'foobaa'

        # add a data object record
        meta0 = db.add_data_object(c_hash, None, 'data_type', 'data_format', 'created_by', None, owner, False, False)
        meta1 = db.add_data_object(c_hash, None, 'data_type', 'data_format', 'created_by', None, owner, False, False)
        assert(meta0 is not None)
        assert(meta1 is not None)
        valid_obj_id = meta0['obj_id']
        invalid_obj_id = 'invalid obj id'

        result = db.get_object_by_id(valid_obj_id)
        assert(result is not None)

        result = db.get_object_by_id(invalid_obj_id)
        assert(result is None)

        result = db.get_objects_by_content_hash(c_hash)
        assert(result is not None)
        assert(len(result) == 2)

        result = db.get_objects_by_content_hash('invalid c_hash')
        assert(result is not None)
        assert(len(result) == 0)

        try:
            db.remove_data_object(invalid_obj_id)
            assert False

        except DataObjectNotFoundError:
            assert True

        try:
            result = db.remove_data_object(valid_obj_id)
            assert(result is not None)

        except DataObjectNotFoundError:
            assert False

        try:
            db.remove_data_object(valid_obj_id)
            assert False

        except DataObjectNotFoundError:
            assert True

    def test_get_update_ownership(self):
        db: NodeDBService = self._node.db
        owner: Identity = self._node.identity
        new_owner: Identity = self._extras[0].identity

        meta = db.add_data_object('foobaa2', None, 'data_type', 'data_format', 'created_by', None, owner, False, False)
        obj_id = meta['obj_id']

        result = db.get_owner(obj_id)
        assert(result is not None)
        assert(result.id == owner.id)

        try:
            db.get_owner('invalid id')
            assert False

        except DataObjectNotFoundError:
            assert True

        db.update_ownership(obj_id, new_owner)
        result = db.get_owner(obj_id)
        assert(result is not None)
        assert(result.id == new_owner.id)

        try:
            db.update_ownership('invalid id', owner)
            assert False

        except DataObjectNotFoundError:
            assert True

    def test_get_all_update_identity(self):
        db: NodeDBService = self._node.db
        identity = self._node.identity
        old_name = identity.name
        new_name = identity.name+'2'

        # get all identities
        result = db.get_all_identities()
        assert(result is not None)
        assert(len(result) == 3)

        # get specific identity
        result = db.get_identity(identity.id)
        assert(result is not None)
        assert(result.id == identity.id)
        assert(result.name != new_name)

        # update identity
        identity = self._node.keystore.update_profile(name=new_name)
        db.update_identity(identity)

        # get identity and check name
        result = db.get_identity(identity.id)
        assert(result is not None)
        assert(result.id == identity.id)
        assert(result.name == new_name)

        # update identity
        identity = self._node.keystore.update_profile(name=old_name)
        db.update_identity(identity)

    def test_update_network(self):
        pass

    def test_remove_network(self):
        pass

    def test_resolve_network(self):
        pass

    def test_get_network(self):
        pass

    def test_get_network_all(self):
        pass

    def test_add_recipe(self):
        pass

    def test_get_recipe(self):
        pass

    def test_get_provenance(self):
        pass

    def test_create_sync_snapshot(self):
        pass

    def test_node_self_awareness(self):
        identities = self._node.db.get_all_identities()
        assert(len(identities) == 1 + len(self._extras))
        assert(identities[self._node.identity.id].name == 'node')

        network = self._node.db.get_network_all()
        assert(len(network) == 1)
        assert(network[0].iid == self._node.identity.id)

    def test_different_address(self):
        p2p_address = PortMaster.generate_p2p_address(self.host)

        # manually create a node on a certain address and make it known to the self.node
        node0 = Node(self._extras[0], os.path.join(self.wd_path, 'node0'))
        node0.startup(p2p_address, enable_dor=False, enable_rti=False, rest_address=None)
        node0.join_network(self._node.p2p.address())

        # the self.node should know of 2 nodes now
        network = self._db.get_network()
        network = [item['iid'] for item in network]
        assert(len(network) == 2)
        assert(self._node.identity.id in network)
        assert(node0.identity.id in network)

        # shutdown the first node silently (i.e., not leaving the network) - this emulates what happens
        # when a node suddenly crashes for example.
        node0.shutdown(leave_network=False)

        # the self.node should still know 2 nodes
        network = self._db.get_network()
        network = [item['iid'] for item in network]
        assert(len(network) == 2)
        assert(self._node.identity.id in network)
        assert(node0.identity.id in network)

        # manually create a second node, using the same address but a different keystore
        node1 = Node(self._extras[1], os.path.join(self.wd_path, 'node1'))
        node1.startup(p2p_address, enable_dor=False, enable_rti=False, rest_address=None)

        # at this point node1 should only know about itself
        network = node1.db.get_network_all()
        network = [item.iid for item in network]
        assert(len(network) == 1)
        assert(node1.identity.id in network)

        # perform the join
        node1.join_network(self._node.p2p.address())

        # the self.node should know still only know of 2 nodes now (the first node should be replaced)
        network = self._db.get_network()
        network = [item['iid'] for item in network]
        assert(len(network) == 2)
        assert(self._node.identity.id in network)
        assert(node1.identity.id in network)

        node0.shutdown()
        node1.shutdown()


class NodeDBServiceTestCase2(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

    def tearDown(self):
        self.cleanup()

    def test_update_identity(self):
        # check identities known to nodes (they should all know of each other)
        nodes = self.create_nodes(3, perform_join=True)
        for node in nodes:
            ids = node.db.get_all_identities()
            print(ids)
            assert(len(ids) == 3)

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
        nodes[0].db.protocol.update_peer(nodes[1].p2p.address(), reciprocate=False, forward=False)
        time.sleep(2)

        # send snapshot from node 1 to node 2
        nodes[1].db.protocol.update_peer(nodes[2].p2p.address(), reciprocate=False, forward=False)
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
            nodes[i].db.update_identity(extras[i].identity)

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

        iid0 = nodes[0].identity.id

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
