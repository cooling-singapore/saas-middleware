import unittest
import logging
import os

from saas.dor.proxy import EndpointProxy
from tests.testing_environment import TestingEnvironment
from saas.utilities.general_helpers import object_to_ordered_list
from saas.node import Node
from saas.dor.protocol import DataObjectRepositoryP2PProtocol

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

env = TestingEnvironment.get_instance('../config/testing-config.json')
logger = logging.getLogger(__name__)


class DORBlueprintTestCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env.start_flask_app()

    @classmethod
    def tearDownClass(cls):
        env.stop_flask_app()

    def setUp(self):
        env.prepare_working_directory()
        self.keys = env.generate_keys(3)
        self.proxy = EndpointProxy(f"{env.app_service_rest_host}:{env.app_service_rest_port}", self.keys[0])

    def tearDown(self):
        pass

    def test_add_delete_data_object(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = env.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id = self.proxy.add_data_object(test_file_path, self.keys[1], data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        # get the descriptor of the data object
        descriptor1 = self.proxy.get_descriptor(obj_id)
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        # delete the data object
        descriptor2 = self.proxy.delete(obj_id, self.keys[1])
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_grant_revoke_access(self):
        logger.info(f"keys[0].iid={self.keys[0].iid}")
        logger.info(f"keys[1].iid={self.keys[1].iid}")
        logger.info(f"keys[2].iid={self.keys[2].iid}")

        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = env.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        obj_id = self.proxy.add_data_object(test_file_path, self.keys[1], data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        permissions = self.proxy.get_access_permissions(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 0

        reply = self.proxy.grant_access(obj_id, self.keys[0], self.keys[2], 'permission')
        assert reply == 'Authorisation failed.'

        permissions = self.proxy.get_access_permissions(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 0

        reply = self.proxy.grant_access(obj_id, self.keys[1], self.keys[2], 'permission')
        assert reply == 'Access granted.'

        permissions = self.proxy.get_access_permissions(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 1
        assert self.keys[2].iid in permissions

        reply = self.proxy.revoke_access(obj_id, self.keys[1], self.keys[2])
        assert reply == 'Access revoked.'

        permissions = self.proxy.get_access_permissions(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 0

        descriptor = self.proxy.delete(obj_id, self.keys[1])
        logger.info(f"descriptor={descriptor}")
        assert descriptor is not None

    def test_transfer_ownership(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = env.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id = self.proxy.add_data_object(test_file_path, self.keys[1], data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        owner_info = self.proxy.get_owner(obj_id)
        logger.info(f"owner_info={owner_info}")
        assert owner_info['owner_iid'] == self.keys[1].iid

        reply = self.proxy.transfer_ownership(obj_id, self.keys[0], self.keys[2])
        assert reply == 'Authorisation failed.'

        reply = self.proxy.transfer_ownership(obj_id, self.keys[1], self.keys[2])
        logger.info(f"reply={reply}")
        assert reply == f"Ownership of data object '{obj_id}' transferred to '{self.keys[2].public_as_string()}'."

        owner_info = self.proxy.get_owner(obj_id)
        logger.info(f"owner_info={owner_info}")
        assert owner_info['owner_iid'] == self.keys[2].iid

        descriptor = self.proxy.delete(obj_id, self.keys[1])
        logger.info(f"descriptor={descriptor}")
        assert descriptor is None

        descriptor = self.proxy.delete(obj_id, self.keys[2])
        logger.info(f"descriptor={descriptor}")
        assert descriptor is not None

    def test_get_data_object(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = env.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id = self.proxy.add_data_object(test_file_path, self.keys[1], data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        descriptor1 = self.proxy.get_descriptor(obj_id)
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        destination = os.path.join(env.wd_path, 'test_copy.dat')
        reply = self.proxy.get_content(obj_id, self.keys[0], destination)
        assert reply == 401
        assert not os.path.exists(destination)

        reply = self.proxy.get_content(obj_id, self.keys[1], destination)
        assert reply == 200
        assert os.path.isfile(destination)

        descriptor2 = self.proxy.delete(obj_id, self.keys[1])
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_fetch_data_object(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = env.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id = self.proxy.add_data_object(test_file_path, self.keys[1], data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        descriptor1 = self.proxy.get_descriptor(obj_id)
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        # create the receiving node
        receiver_wd_path = os.path.join(env.wd_path, 'receiver')
        node = Node('receiver', receiver_wd_path, env.rest_api_address)
        node.initialise_identity(receiver_wd_path)
        node.start_server(env.p2p_server_address)

        peer_address = (env.app_service_p2p_host, env.app_service_p2p_port)

        protocol = DataObjectRepositoryP2PProtocol(node)
        c_hash = protocol.send_fetch(peer_address, 'abcdef')
        assert not c_hash

        c_hash = protocol.send_fetch(peer_address, obj_id)
        assert c_hash

        destination_descriptor_path = os.path.join(receiver_wd_path, node.dor.infix_cache_path, f"{obj_id}.descriptor")
        destination_content_path = os.path.join(receiver_wd_path, node.dor.infix_cache_path, f"{c_hash}.content")
        assert os.path.isfile(destination_descriptor_path)
        assert os.path.isfile(destination_content_path)

        node.stop_server()

        descriptor2 = self.proxy.delete(obj_id, self.keys[1])
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_add_tag_delete_data_object(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = env.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id = self.proxy.add_data_object(test_file_path, self.keys[1], data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        # get tags for that data object
        tags = self.proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert tags == {}

        # update tags for that data object
        self.proxy.update_tags(obj_id, self.keys[1], {
            'a': '123',
            'b': '567'
        })
        tags = self.proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 2
        assert 'a' in tags
        assert 'b' in tags
        assert tags['a'] == '123'

        # update tags for that data object
        self.proxy.update_tags(obj_id, self.keys[1], {
            'a': '567'
        })
        tags = self.proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 2
        assert 'a' in tags
        assert 'b' in tags
        assert tags['a'] == '567'

        # remove a tag
        self.proxy.remove_tags(obj_id, self.keys[1], ['b'])
        tags = self.proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 1
        assert 'a' in tags
        assert 'b' not in tags

        # delete the data object
        descriptor = self.proxy.delete(obj_id, self.keys[1])
        logger.info(f"descriptor={descriptor}")
        assert descriptor is not None

        tags = self.proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 0

    def test_add_tag_search_delete_data_object(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path0 = env.generate_random_file('test000.dat', 1024*1024)
        test_file_path1 = env.generate_random_file('test001.dat', 1024*1024)

        # create the data object
        obj_id0 = self.proxy.add_data_object(test_file_path0, self.keys[1], data_type, data_format, created_by, created_t)
        logger.info(f"obj_id0: {obj_id0}")
        assert obj_id0 is not None

        # update tags for that data object
        self.proxy.update_tags(obj_id0, self.keys[1], {
            'hellox': '123',
            'whazzup': '567',
            'a': '123'
        })
        tags0 = self.proxy.get_tags(obj_id0)
        logger.info(f"tags0={tags0}")
        assert len(tags0) == 3

        # create the data object 1
        obj_id1 = self.proxy.add_data_object(test_file_path1, self.keys[1], data_type, data_format, created_by, created_t)
        logger.info(f"obj_id1: {obj_id1}")
        assert obj_id1 is not None

        # update tags for that data object
        self.proxy.update_tags(obj_id1, self.keys[1], {
            'hello': '123',
            'world': '567',
            'a': '124'
        })
        tags1 = self.proxy.get_tags(obj_id1)
        logger.info(f"tags1={tags1}")
        assert len(tags1) == 3

        # search for data objects
        result = self.proxy.search_by_tags("hello")
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id1 in result

        result = self.proxy.search_by_tags("hello%")
        logger.info(f"result={result}")
        assert len(result) == 2
        assert obj_id0 in result
        assert obj_id1 in result

        result = self.proxy.search_by_tags("hel%")
        logger.info(f"result={result}")
        assert len(result) == 2
        assert obj_id0 in result
        assert obj_id1 in result

        result = self.proxy.search_by_tags("whazzup")
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id0 in result

        result = self.proxy.search_by_tags("whazzup_")
        logger.info(f"result={result}")
        assert len(result) == 0

        result = self.proxy.search_by_tags("a", "123")
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id0 in result

        result = self.proxy.search_by_tags("a", "124")
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id1 in result

        result = self.proxy.search_by_tags("a", "12%")
        logger.info(f"result={result}")
        assert len(result) == 2
        assert obj_id0 in result
        assert obj_id1 in result

        # test the case where no criteria are given
        result = self.proxy.search_by_tags()
        logger.info(f"result={result}")
        assert len(result) == 0

        # delete the data object 0
        descriptor0 = self.proxy.delete(obj_id0, self.keys[1])
        logger.info(f"descriptor0={descriptor0}")
        assert descriptor0 is not None

        # delete the data object 1
        descriptor1 = self.proxy.delete(obj_id1, self.keys[1])
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        tags0 = self.proxy.get_tags(obj_id0)
        logger.info(f"tags0={tags0}")
        assert len(tags0) == 0

        tags1 = self.proxy.get_tags(obj_id1)
        logger.info(f"tags1={tags1}")
        assert len(tags1) == 0


if __name__ == '__main__':
    unittest.main()
