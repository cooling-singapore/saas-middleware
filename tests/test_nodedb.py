import unittest
import logging
import os
import time

from saas.cryptography.eckeypair import ECKeyPair
from tests.testing_environment import TestingEnvironment
from saas.node import Node
from saas.nodedb.nodedb import NodeDB

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)
env = TestingEnvironment.get_instance('../config/testing-config.json')
n_nodes = 2


class NodeDBTestCase(unittest.TestCase):
    def setUp(self):
        env.prepare_working_directory()

        self.nodes = []
        for i in range(0, n_nodes):
            name = f"node_{i}"
            datastore_path = os.path.join(env.wd_path, name)

            logger.info(f"creating node '{name}'")
            node = Node(name, datastore_path, env.rest_api_address)
            node.initialise_identity(env.password)
            node.start_server((env.p2p_server_address[0], env.p2p_server_address[1] + i))
            node.initialise_registry(env.p2p_server_address)
            self.nodes.append(node)

        # give it some time to settle
        time.sleep(2)

    def tearDown(self):
        for node in self.nodes:
            logger.info(f"stopping db '{node.name}'")
            node.stop_server()

    def test_add_update_remove_tags(self):
        node = self.nodes[0]

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
        node = self.nodes[0]

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
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        node0.db.update_tags('aaa', [
            {'key': 'k0', 'value': 'v0'}
        ], propagate=True)
        time.sleep(1)

        tags = node0.db.get_tags('aaa')
        assert(len(tags) == 1)
        assert('k0' in tags)

        tags = node1.db.get_tags('aaa')
        assert(len(tags) == 1)
        assert('k0' in tags)

        node1.db.remove_tags('aaa', ['k0'], propagate=True)
        time.sleep(1)

        tags = node0.db.get_tags('aaa')
        assert(len(tags) == 0)

        tags = node1.db.get_tags('aaa')
        assert(len(tags) == 0)

    def test_update_public_key(self):
        node = self.nodes[0]

        key = ECKeyPair.create_new()

        result = node.db.get_public_key(key.iid)
        assert(result is None)

        node.db.update_public_key(key.iid, key.public_as_string(), propagate=False)
        node.db.update_public_key(key.iid, key.public_as_string(), propagate=False)

        result = node.db.get_public_key(key.iid)
        assert(result is not None)
        assert(key.iid == result.iid)

    def test_propagate_public_key_update(self):
        node0 = self.nodes[0]
        node1 = self.nodes[0]

        key = ECKeyPair.create_new()

        result = node0.db.get_public_key(key.iid)
        assert(result is None)

        result = node1.db.get_public_key(key.iid)
        assert(result is None)

        node1.db.update_public_key(key.iid, key.public_as_string(), propagate=True)
        time.sleep(1)

        result = node0.db.get_public_key(key.iid)
        assert(result is not None)
        assert(key.iid == result.iid)

        result = node1.db.get_public_key(key.iid)
        assert(result is not None)
        assert(key.iid == result.iid)

    def test_grant_revoke_permissions(self):
        node = self.nodes[0]

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


if __name__ == '__main__':
    unittest.main()
