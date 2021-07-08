import unittest
import logging
import os

from saas.cryptography.helpers import symmetric_encrypt, symmetric_decrypt
from saas.dor.blueprint import DORProxy
from saas.nodedb.blueprint import NodeDBProxy
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
        self.dor_proxy = DORProxy(self.node.rest.address(), self.node)
        self.db_proxy = NodeDBProxy(self.node.rest.address(), self.node)

        # create extra keystores and make them known to the node
        self.extras = self.create_keystores(3)
        for extra in self.extras:
            signature = extra.update()
            identity = extra.identity()
            self.db_proxy.update_identity(identity, signature)

    def tearDown(self):
        self.cleanup()

    def test_add_delete_data_object(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id, descriptor = self.dor_proxy.add_data_object(test_file_path, self.extras[0].identity(),
                                                            False, False, None,
                                                            data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        # get the descriptor of the data object
        descriptor1 = self.dor_proxy.get_descriptor(obj_id)
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        # delete the data object
        descriptor2 = self.dor_proxy.delete_data_object(obj_id, self.extras[0].signing_key())
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_grant_revoke_access(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        obj_id, _ = self.dor_proxy.add_data_object(test_file_path, self.extras[1].identity(),
                                                   False, False, None,
                                                   data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        permissions = self.dor_proxy.get_access_overview(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 1

        reply = self.dor_proxy.grant_access(obj_id, self.extras[0].signing_key(),
                                            self.extras[2].identity(), 'permission')
        assert reply == 'Authorisation failed.'

        permissions = self.dor_proxy.get_access_overview(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 1

        reply = self.dor_proxy.grant_access(obj_id, self.extras[1].signing_key(),
                                            self.extras[2].identity(), 'permission')
        assert reply is not None
        assert reply[obj_id] == self.extras[2].identity().id()

        permissions = self.dor_proxy.get_access_overview(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 2
        assert self.extras[2].identity().id() in permissions

        reply = self.dor_proxy.revoke_access(obj_id, self.extras[1].signing_key(),
                                             self.extras[2].identity())
        assert reply is not None
        assert reply[obj_id] == self.extras[2].identity().id()

        permissions = self.dor_proxy.get_access_overview(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 1

        descriptor = self.dor_proxy.delete_data_object(obj_id, self.extras[1].signing_key())
        logger.info(f"descriptor={descriptor}")
        assert descriptor is not None

    def test_transfer_ownership(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id, _ = self.dor_proxy.add_data_object(test_file_path, self.extras[1].identity(),
                                                   False, False, None,
                                                   data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        owner_info = self.dor_proxy.get_owner(obj_id)
        logger.info(f"owner_info={owner_info}")
        assert owner_info['owner_iid'] == self.extras[1].identity().id()

        reply = self.dor_proxy.transfer_ownership(obj_id, self.extras[0].signing_key(), self.extras[2].identity())
        assert reply == 'Authorisation failed.'

        reply = self.dor_proxy.transfer_ownership(obj_id, self.extras[1].signing_key(), self.extras[2].identity())
        logger.info(f"reply={reply}")
        assert reply == f"Ownership of data object '{obj_id}' transferred to '{self.extras[2].identity().id()}'."

        owner_info = self.dor_proxy.get_owner(obj_id)
        logger.info(f"owner_info={owner_info}")
        assert owner_info['owner_iid'] == self.extras[2].identity().id()

        descriptor = self.dor_proxy.delete_data_object(obj_id, self.extras[1].signing_key())
        logger.info(f"descriptor={descriptor}")
        assert descriptor == 'Authorisation failed.'

        descriptor = self.dor_proxy.delete_data_object(obj_id, self.extras[2].signing_key())
        logger.info(f"descriptor={descriptor}")
        assert descriptor is not None

    def test_get_content(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id, _ = self.dor_proxy.add_data_object(test_file_path, self.extras[1].identity(),
                                                   False, False, None,
                                                   data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        descriptor1 = self.dor_proxy.get_descriptor(obj_id)
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        # only the OWNER can get the content via the REST API

        destination = os.path.join(self.wd_path, 'test_copy.dat')
        reply = self.dor_proxy.get_content(obj_id, self.extras[0].signing_key(), destination)
        assert reply == 401
        assert not os.path.exists(destination)

        reply = self.dor_proxy.get_content(obj_id, self.extras[1].signing_key(), destination)
        assert reply == 200
        assert os.path.isfile(destination)

        descriptor2 = self.dor_proxy.delete_data_object(obj_id, self.extras[1].signing_key())
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_content_encryption(self):
        key1s = self.extras[1].signing_key()
        key2s = self.extras[2].signing_key()
        key1e = self.extras[1].encryption_key()
        key2e = self.extras[1].encryption_key()

        # create content for the data object and encrypt it
        content_plain = "my little secret..."
        content_enc, content_key = symmetric_encrypt(content_plain.encode('utf-8'))
        logger.info(f"content_plain={content_plain}")
        logger.info(f"content_enc={content_enc}")
        logger.info(f"content_key={content_key}")
        content_enc_path = self.create_file_with_content('content.enc', content_enc.decode('utf-8'))

        # protect the content key
        protected_content_key1 = key1e.encrypt(content_key, base64_encoded=True).decode('utf-8')
        protected_content_key2 = key2e.encrypt(content_key, base64_encoded=True).decode('utf-8')
        logger.info(f"protected_content_key1={protected_content_key1}")
        logger.info(f"protected_content_key2={protected_content_key2}")

        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # add data object with the encrypted content
        obj_id, descriptor = self.dor_proxy.add_data_object(content_enc_path, self.extras[1].identity(),
                                                            False, True, protected_content_key1,
                                                            data_type, data_format, created_by, created_t)
        assert obj_id is not None
        assert descriptor is not None
        logger.info(f"descriptor={descriptor}")

        # only the CURRENT owner can get the content key
        protected_content_key = self.dor_proxy.get_access_permission(obj_id, self.extras[1].identity())
        logger.info(f"protected_content_key={protected_content_key}")
        assert(protected_content_key == protected_content_key1)

        # we should be able to use this content key to decrypt the content
        unprotected_content_key = key1e.decrypt(protected_content_key.encode('utf-8'), base64_encoded=True)
        unprotected_content = symmetric_decrypt(content_enc, unprotected_content_key).decode('utf-8')
        assert(unprotected_content == content_plain)

        # transfer ownership now
        self.dor_proxy.transfer_ownership(obj_id, key1s, self.extras[2].identity(), protected_content_key2)

        # the old owner cannot get the content key (or content) any longer
        protected_content_key = self.dor_proxy.get_access_permission(obj_id, self.extras[1].identity())
        assert(protected_content_key is None)

        # only the NEW owner can get the content key
        protected_content_key = self.dor_proxy.get_access_permission(obj_id, self.extras[2].identity())
        logger.info(f"protected_content_key={protected_content_key}")
        assert(protected_content_key == protected_content_key2)

        # we should be able to use this content key to decrypt the content
        unprotected_content_key = key2e.decrypt(protected_content_key.encode('utf-8'), base64_encoded=True)
        unprotected_content = symmetric_decrypt(content_enc, unprotected_content_key).decode('utf-8')
        assert(unprotected_content == content_plain)

        descriptor = self.dor_proxy.delete_data_object(obj_id, key2s)
        assert descriptor is not None
        logger.info(f"descriptor={descriptor}")

    def test_fetch_data_object(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object (set access_restricted to True which means permission needs to be granted
        # before fetching is possible)
        obj_id, _ = self.dor_proxy.add_data_object(test_file_path, self.extras[1].identity(),
                                                   True, False, None,
                                                   data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        descriptor1 = self.dor_proxy.get_descriptor(obj_id)
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        # create the receiving node
        receiver = self.get_node('receiver')
        receiver_identity, signature = receiver.update_identity()
        self.db_proxy.update_identity(receiver_identity, signature)

        # try to fetch a data object that doesn't exist
        protocol = DataObjectRepositoryP2PProtocol(receiver)
        fake_obj_id = 'abcdef'
        descriptor_path = os.path.join(self.wd_path, f"{fake_obj_id}.descriptor")
        content_path = os.path.join(self.wd_path, fake_obj_id)
        result = protocol.send_fetch(self.node.p2p.address(), fake_obj_id,
                                     destination_descriptor_path=descriptor_path,
                                     destination_content_path=content_path)
        assert result['code'] != 200

        descriptor_path = os.path.join(self.wd_path, f"{obj_id}.descriptor")
        content_path = os.path.join(self.wd_path, f"{obj_id}.content")

        # the receiver does not have permission at this point to receive the data object
        result = protocol.send_fetch(self.node.p2p.address(), obj_id,
                                     destination_descriptor_path=descriptor_path,
                                     destination_content_path=content_path)
        assert result['code'] != 200

        # grant permission
        result = self.dor_proxy.grant_access(obj_id, self.extras[1].signing_key(), receiver_identity)
        assert result[obj_id] == receiver_identity.id()

        # create user signature to delegate access rights
        token = f"{receiver_identity.id()}:{obj_id}"
        signature = receiver.signing_key().sign(token.encode('utf-8'))

        # the receiver does have permission at this point to receive the data object
        result = protocol.send_fetch(self.node.p2p.address(), obj_id,
                                     destination_descriptor_path=descriptor_path,
                                     destination_content_path=content_path,
                                     user_signature=signature, user_iid=receiver_identity.id())
        assert result['code'] == 200
        assert os.path.isfile(descriptor_path)
        assert os.path.isfile(content_path)

        descriptor2 = self.dor_proxy.delete_data_object(obj_id, self.extras[1].signing_key())
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_add_tag_delete_data_object(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        ref_obj_id = 'ef1bde41ebd7bc58a6e68db2d3c49d33f999d67fcd0568b6fc7723363664e478'

        # create the data object
        obj_id, _ = self.dor_proxy.add_data_object(test_file_path, self.extras[1].identity(),
                                                   False, False, None,
                                                   data_type, data_format, created_by, created_t)
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        # get tags for that data object
        tags = self.dor_proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert tags == {}

        # update tags for that data object
        self.dor_proxy.update_tags(obj_id, self.extras[1].signing_key(), {
            'a': '123',
            'b': '567'
        })
        tags = self.dor_proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 2
        assert 'a' in tags
        assert 'b' in tags
        assert tags['a'] == '123'

        # update tags for that data object
        self.dor_proxy.update_tags(obj_id, self.extras[1].signing_key(), {
            'a': '567'
        })
        tags = self.dor_proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 2
        assert 'a' in tags
        assert 'b' in tags
        assert tags['a'] == '567'

        # remove a tag
        self.dor_proxy.remove_tags(obj_id, self.extras[1].signing_key(), ['b'])
        tags = self.dor_proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 1
        assert 'a' in tags
        assert 'b' not in tags

        # delete the data object
        descriptor = self.dor_proxy.delete_data_object(obj_id, self.extras[1].signing_key())
        logger.info(f"descriptor={descriptor}")
        assert descriptor is not None

        tags = self.dor_proxy.get_tags(obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 0

    def test_add_tag_search_delete_data_object(self):
        data_type = 'map'
        data_format = 'json'
        created_t = 21342342
        created_by = 'heiko'

        # create some test data
        test_file_path0 = self.generate_random_file('test000.dat', 1024*1024)
        test_file_path1 = self.generate_random_file('test001.dat', 1024*1024)

        # create the data object
        obj_id0, _ = self.dor_proxy.add_data_object(test_file_path0, self.extras[1].identity(),
                                                    False, False, None,
                                                    data_type, data_format, created_by, created_t)
        logger.info(f"obj_id0: {obj_id0}")
        assert obj_id0 is not None

        # update tags for that data object
        self.dor_proxy.update_tags(obj_id0, self.extras[1].signing_key(), {
            'hellox': '123',
            'whazzup': '567',
            'a': '123'
        })
        tags0 = self.dor_proxy.get_tags(obj_id0)
        logger.info(f"tags0={tags0}")
        assert len(tags0) == 3

        # create the data object 1
        obj_id1, _ = self.dor_proxy.add_data_object(test_file_path1, self.extras[1].identity(),
                                                    False, False, None,
                                                    data_type, data_format, created_by, created_t)
        logger.info(f"obj_id1: {obj_id1}")
        assert obj_id1 is not None

        # update tags for that data object
        self.dor_proxy.update_tags(obj_id1, self.extras[1].signing_key(), {
            'hello': '123',
            'world': '567',
            'a': '124'
        })
        tags1 = self.dor_proxy.get_tags(obj_id1)
        logger.info(f"tags1={tags1}")
        assert len(tags1) == 3

        # search for data objects
        result = self.dor_proxy.search_by_tags("hello")
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id1 in result

        result = self.dor_proxy.search_by_tags("hello%")
        logger.info(f"result={result}")
        assert len(result) == 2
        assert obj_id0 in result
        assert obj_id1 in result

        result = self.dor_proxy.search_by_tags("hel%")
        logger.info(f"result={result}")
        assert len(result) == 2
        assert obj_id0 in result
        assert obj_id1 in result

        result = self.dor_proxy.search_by_tags("whazzup")
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id0 in result

        result = self.dor_proxy.search_by_tags("whazzup_")
        logger.info(f"result={result}")
        assert len(result) == 0

        result = self.dor_proxy.search_by_tags("a", "123")
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id0 in result

        result = self.dor_proxy.search_by_tags("a", "124")
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id1 in result

        result = self.dor_proxy.search_by_tags("a", "12%")
        logger.info(f"result={result}")
        assert len(result) == 2
        assert obj_id0 in result
        assert obj_id1 in result

        # test the case where no criteria are given
        result = self.dor_proxy.search_by_tags()
        logger.info(f"result={result}")
        assert len(result) == 0

        # delete the data object 0
        descriptor0 = self.dor_proxy.delete_data_object(obj_id0, self.extras[1].signing_key())
        logger.info(f"descriptor0={descriptor0}")
        assert descriptor0 is not None

        # delete the data object 1
        descriptor1 = self.dor_proxy.delete_data_object(obj_id1, self.extras[1].signing_key())
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        tags0 = self.dor_proxy.get_tags(obj_id0)
        logger.info(f"tags0={tags0}")
        assert len(tags0) == 0

        tags1 = self.dor_proxy.get_tags(obj_id1)
        logger.info(f"tags1={tags1}")
        assert len(tags1) == 0


if __name__ == '__main__':
    unittest.main()
