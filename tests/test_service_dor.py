import unittest
import logging
import os

from saas.cryptography.eckeypair import ECKeyPair
from saas.dor.blueprint import DORProxy
from tests.base_testcase import TestCaseBase
from saas.utilities.general_helpers import object_to_ordered_list
from saas.dor.protocol import DataObjectRepositoryP2PProtocol

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class DORServiceTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        self.node = self.get_node('node', enable_rest=True)
        self.proxy = DORProxy(self.node.rest.address(), self.node.identity())

    def tearDown(self):
        self.cleanup()

    def test_add_delete_data_object(self):
        owner = ECKeyPair.create_new()

        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id, descriptor = self.proxy.add_data_object(test_file_path, owner, False, False,
                                                        data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        # get the descriptor of the data object
        descriptor1 = self.proxy.get_descriptor(obj_id)
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        # delete the data object
        descriptor2 = self.proxy.delete_data_object(obj_id, owner)
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_grant_revoke_access(self):
        keys = []
        for i in range(3):
            keys.append(ECKeyPair.create_new())

        logger.info(f"keys[0].iid={keys[0].iid}")
        logger.info(f"keys[1].iid={keys[1].iid}")
        logger.info(f"keys[2].iid={keys[2].iid}")

        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        obj_id, _ = self.proxy.add_data_object(test_file_path, keys[1], False, False,
                                               data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        permissions = self.proxy.get_access_list(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 0

        reply = self.proxy.grant_access(obj_id, keys[0], keys[2], 'permission')
        assert reply == 'Authorisation failed.'

        permissions = self.proxy.get_access_list(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 0

        reply = self.proxy.grant_access(obj_id, keys[1], keys[2], 'permission')
        assert reply is not None
        assert reply[obj_id] == keys[2].iid

        permissions = self.proxy.get_access_list(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 1
        assert keys[2].iid in permissions

        reply = self.proxy.revoke_access(obj_id, keys[1], keys[2])
        assert reply is not None
        assert reply[obj_id] == keys[2].iid

        permissions = self.proxy.get_access_list(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 0

        descriptor = self.proxy.delete_data_object(obj_id, keys[1])
        logger.info(f"descriptor={descriptor}")
        assert descriptor is not None

    def test_transfer_ownership(self):
        keys = []
        for i in range(3):
            keys.append(ECKeyPair.create_new())

        logger.info(f"keys[0].iid={keys[0].iid}")
        logger.info(f"keys[1].iid={keys[1].iid}")
        logger.info(f"keys[2].iid={keys[2].iid}")

        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id, _ = self.proxy.add_data_object(test_file_path, keys[1], False, False,
                                               data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        owner_info = self.proxy.get_owner(obj_id)
        logger.info(f"owner_info={owner_info}")
        assert owner_info['owner_iid'] == keys[1].iid

        reply = self.proxy.transfer_ownership(obj_id, keys[0], keys[2])
        assert reply == 'Authorisation failed.'

        reply = self.proxy.transfer_ownership(obj_id, keys[1], keys[2])
        logger.info(f"reply={reply}")
        assert reply == f"Ownership of data object '{obj_id}' transferred to '{keys[2].public_as_string()}'."

        owner_info = self.proxy.get_owner(obj_id)
        logger.info(f"owner_info={owner_info}")
        assert owner_info['owner_iid'] == keys[2].iid

        descriptor = self.proxy.delete_data_object(obj_id, keys[1])
        logger.info(f"descriptor={descriptor}")
        assert descriptor is None

        descriptor = self.proxy.delete_data_object(obj_id, keys[2])
        logger.info(f"descriptor={descriptor}")
        assert descriptor is not None

    def test_get_data_object(self):
        keys = []
        for i in range(2):
            keys.append(ECKeyPair.create_new())

        logger.info(f"keys[0].iid={keys[0].iid}")
        logger.info(f"keys[1].iid={keys[1].iid}")

        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id, _ = self.proxy.add_data_object(test_file_path, keys[1], False, False,
                                               data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        descriptor1 = self.proxy.get_descriptor(obj_id)
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        # only the OWNER can get the content via the REST API

        destination = os.path.join(self.wd_path, 'test_copy.dat')
        reply = self.proxy.get_content(obj_id, keys[0], destination)
        assert reply == 401
        assert not os.path.exists(destination)

        reply = self.proxy.get_content(obj_id, keys[1], destination)
        assert reply == 200
        assert os.path.isfile(destination)

        descriptor2 = self.proxy.delete_data_object(obj_id, keys[1])
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_fetch_data_object(self):
        owner = ECKeyPair.create_new()
        logger.info(f"owner.iid={owner.iid}")

        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object (set access_restricted to True which means permission needs to be granted
        # before fetching is possible)
        obj_id, _ = self.proxy.add_data_object(test_file_path, owner, True, False,
                                               data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        descriptor1 = self.proxy.get_descriptor(obj_id)
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        # create the receiving node
        receiver = self.get_node('receiver')

        # try to fetch a data object that doesn't exist
        protocol = DataObjectRepositoryP2PProtocol(receiver)
        c_hash = protocol.send_fetch(self.node.p2p.address(), 'abcdef')
        assert c_hash is None

        # the receiver does not have permission at this point to receive the data object
        c_hash = protocol.send_fetch(self.node.p2p.address(), obj_id)
        assert c_hash is None

        # grant permission
        result = self.proxy.grant_access(obj_id, owner, receiver.identity())
        assert result[obj_id] == receiver.id()

        # the receiver does not have permission at this point to receive the data object
        c_hash = protocol.send_fetch(self.node.p2p.address(), obj_id)
        assert c_hash is not None

        destination_descriptor_path = os.path.join(receiver.datastore(),
                                                   receiver.dor.infix_cache_path, f"{obj_id}.descriptor")
        destination_content_path = os.path.join(receiver.datastore(),
                                                receiver.dor.infix_cache_path, f"{c_hash}.content")
        assert os.path.isfile(destination_descriptor_path)
        assert os.path.isfile(destination_content_path)

        descriptor2 = self.proxy.delete_data_object(obj_id, owner)
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_add_tag_delete_data_object(self):
        owner = ECKeyPair.create_new()
        logger.info(f"owner.iid={owner.iid}")

        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id, _ = self.proxy.add_data_object(test_file_path, owner, False, False,
                                               data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        # get tags for that data object
        tags = self.proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert tags == {}

        # update tags for that data object
        self.proxy.update_tags(obj_id, owner, {
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
        self.proxy.update_tags(obj_id, owner, {
            'a': '567'
        })
        tags = self.proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 2
        assert 'a' in tags
        assert 'b' in tags
        assert tags['a'] == '567'

        # remove a tag
        self.proxy.remove_tags(obj_id, owner, ['b'])
        tags = self.proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 1
        assert 'a' in tags
        assert 'b' not in tags

        # delete the data object
        descriptor = self.proxy.delete_data_object(obj_id, owner)
        logger.info(f"descriptor={descriptor}")
        assert descriptor is not None

        tags = self.proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 0

    def test_add_tag_search_delete_data_object(self):
        owner = ECKeyPair.create_new()
        logger.info(f"owner.iid={owner.iid}")

        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path0 = self.generate_random_file('test000.dat', 1024*1024)
        test_file_path1 = self.generate_random_file('test001.dat', 1024*1024)

        # create the data object
        obj_id0, _ = self.proxy.add_data_object(test_file_path0, owner, False, False,
                                                data_type, data_format, created_by, created_t)
        logger.info(f"obj_id0: {obj_id0}")
        assert obj_id0 is not None

        # update tags for that data object
        self.proxy.update_tags(obj_id0, owner, {
            'hellox': '123',
            'whazzup': '567',
            'a': '123'
        })
        tags0 = self.proxy.get_tags(obj_id0)
        logger.info(f"tags0={tags0}")
        assert len(tags0) == 3

        # create the data object 1
        obj_id1, _ = self.proxy.add_data_object(test_file_path1, owner, False, False,
                                                data_type, data_format, created_by, created_t)
        logger.info(f"obj_id1: {obj_id1}")
        assert obj_id1 is not None

        # update tags for that data object
        self.proxy.update_tags(obj_id1, owner, {
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
        descriptor0 = self.proxy.delete_data_object(obj_id0, owner)
        logger.info(f"descriptor0={descriptor0}")
        assert descriptor0 is not None

        # delete the data object 1
        descriptor1 = self.proxy.delete_data_object(obj_id1, owner)
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
