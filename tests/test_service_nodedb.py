import unittest
import logging
import time

from saas.cryptography.eckeypair import ECKeyPair
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

    def test_add_update_remove_tags(self):
        node = self.get_node('node')

        tags = node.db.get_tags('aaa')
        assert(len(tags) == 0)

        node.db.update_tags('aaa', [
            {'key': 'k0', 'value': 'v0'}
        ], propagate=False)

        tags = node.db.get_tags('aaa')
        assert(len(tags) == 1)
        assert('k0' in tags)

        node.db.update_tags('aaa', [
            {'key': 'k1', 'value': 'v1'},
            {'key': 'k2', 'value': 'v2'}
        ], propagate=False)

        tags = node.db.get_tags('aaa')
        assert(len(tags) == 3)

        node.db.update_tags('aaa', [
            {'key': 'k0', 'value': '999'}
        ], propagate=False)

        tags = node.db.get_tags('aaa')
        assert(len(tags) == 3)
        assert(tags['k0'] == '999')

        node.db.remove_tags('aaa', ['k3'], propagate=False)
        tags = node.db.get_tags('aaa')
        assert(len(tags) == 3)

        node.db.remove_tags('bbb', ['k2'], propagate=False)
        tags = node.db.get_tags('aaa')
        assert(len(tags) == 3)

        node.db.remove_tags('aaa', ['k2'], propagate=False)
        tags = node.db.get_tags('aaa')
        assert(len(tags) == 2)

        node.db.remove_tags('aaa', ['k0', 'k1'], propagate=False)
        tags = node.db.get_tags('aaa')
        assert(len(tags) == 0)

    def test_find_data_objects(self):
        node = self.get_node('node')

        node.db.update_tags('aaa', [
            {'key': 'k0', 'value': 'v00'},
            {'key': 'k1', 'value': 'v1'}
        ], propagate=False)

        node.db.update_tags('bbb', [
            {'key': 'k0', 'value': 'v01'},
            {'key': 'k2', 'value': 'v2'}
        ], propagate=False)

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

    def test_propagate_tag_updates(self):
        nodes = self.create_nodes(2)

        nodes[0].db.update_tags('aaa', [
            {'key': 'k0', 'value': 'v0'}
        ], propagate=True)
        time.sleep(1)

        tags = nodes[0].db.get_tags('aaa')
        assert(len(tags) == 1)
        assert('k0' in tags)

        tags = nodes[1].db.get_tags('aaa')
        assert(len(tags) == 1)
        assert('k0' in tags)

        nodes[1].db.remove_tags('aaa', ['k0'], propagate=True)
        time.sleep(1)

        tags = nodes[0].db.get_tags('aaa')
        assert(len(tags) == 0)

        tags = nodes[1].db.get_tags('aaa')
        assert(len(tags) == 0)

    def test_grant_revoke_permissions(self):
        node = self.get_node('node')

        key0 = ECKeyPair.create_new()
        key1 = ECKeyPair.create_new()

        result = node.db.get_access_list('aaa')
        assert(len(result) == 0)

        result = node.db.has_access('aaa', key0)
        assert(not result)

        result = node.db.has_access('aaa', key1)
        assert(not result)

        node.db.grant_access('aaa', key0.public_as_string(), 'permission1')

        result = node.db.get_access_list('aaa')
        assert(len(result) == 1)
        assert(key0.iid in result)

        node.db.revoke_access('aaa', key1.public_as_string())

        result = node.db.get_access_list('aaa')
        assert(len(result) == 1)
        assert(key0.iid in result)

        node.db.revoke_access('aaa', key0.public_as_string())

        result = node.db.get_access_list('aaa')
        assert(len(result) == 0)

    def test_update_identity(self):
        nodes = self.create_nodes(3)
        init_nonce = 0

        # propagate its identity
        nodes[0].update_identity()
        time.sleep(1)

        # check identities known to nodes
        for node in nodes:
            ids = node.db.get_identity_record()
            print(ids)
            assert(len(ids) == 1)

            id0 = ids[0]
            print(f"{id0.iid}:{id0.name}:{id0.email}:{id0.nonce}")
            assert(ids[0].iid == nodes[0].id())
            assert(ids[0].nonce == init_nonce+2)

        # update id of node0 but don't propagate
        nodes[0].update_identity(propagate=False)
        time.sleep(1)
        assert(nodes[0].db.get_identity_record(nodes[0].id()).nonce == init_nonce+3)
        assert(nodes[1].db.get_identity_record(nodes[0].id()).nonce == init_nonce+2)
        assert(nodes[2].db.get_identity_record(nodes[0].id()).nonce == init_nonce+2)

        # update id of node0
        nodes[0].update_identity(propagate=True)
        time.sleep(1)
        assert(nodes[0].db.get_identity_record(nodes[0].id()).nonce == init_nonce+4)
        assert(nodes[1].db.get_identity_record(nodes[0].id()).nonce == init_nonce+4)
        assert(nodes[2].db.get_identity_record(nodes[0].id()).nonce == init_nonce+4)

    def test_snapshot(self):
        nodes = self.create_nodes(3, perform_join=False)
        identities = self.create_identities(3*len(nodes))

        # feed each node with some identities
        for i in range(len(identities)):
            j = i % 3
            nodes[j].db.update_identity(
                identities[i].public_key_as_string(),
                identities[i].name(),
                identities[i].email(),
                0
            )

        # each node should know about 3 identities
        for j in range(len(nodes)):
            records = nodes[j].db.get_identity_record()
            assert(len(records) == 3)

        # send snapshot from node 0 to node 1
        nodes[0].db.send_snapshot(nodes[1].p2p.address())
        time.sleep(2)

        # send snapshot from node 1 to node 2
        nodes[1].db.send_snapshot(nodes[2].p2p.address())
        time.sleep(2)

        # node 0 should know about 3 identities now
        records = nodes[0].db.get_identity_record()
        assert (len(records) == 3)

        # node 1 should know about 6 identities now
        records = nodes[1].db.get_identity_record()
        assert (len(records) == 6)

        # node 2 should know about 9 identities now
        records = nodes[2].db.get_identity_record()
        assert (len(records) == 9)


if __name__ == '__main__':
    unittest.main()
