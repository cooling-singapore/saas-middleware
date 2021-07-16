import unittest
import logging
import os

from saas.cryptography.helpers import symmetric_encrypt, symmetric_decrypt
from saas.dor.blueprint import DORProxy
from saas.nodedb.blueprint import NodeDBProxy
from tests.base_testcase import TestCaseBase
from saas.helpers import object_to_ordered_list
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

        self.node = self.get_node('node', use_credentials=True, enable_rest=True)
        self.dor_proxy = DORProxy(self.node.rest.address())
        self.db_proxy = NodeDBProxy(self.node.rest.address())

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

        reply = self.dor_proxy.grant_access(obj_id, self.extras[0].signing_key(), self.extras[2].identity())
        assert reply == 'Authorisation failed.'

        permissions = self.dor_proxy.get_access_overview(obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 1

        reply = self.dor_proxy.grant_access(obj_id, self.extras[1].signing_key(), self.extras[2].identity())
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
        owner0_k = self.extras[0]
        owner0_signature = owner0_k.update(name="User0", email=self.node.identity().email())
        owner0 = owner0_k.identity()
        self.db_proxy.update_identity(owner0, owner0_signature)

        owner1_k = self.extras[1]
        owner1_signature = owner1_k.update(name="User1", email=self.node.identity().email())
        owner1 = owner1_k.identity()
        self.db_proxy.update_identity(owner1, owner1_signature)

        # create the data object
        test_file_path = self.generate_zero_file('test000.dat', 1024*1024)
        obj_id, _ = self.dor_proxy.add_data_object(test_file_path, owner0,
                                                   False, False, None,
                                                   'map', 'json', owner0.name(), 21342342)
        logger.info(f"obj_id={obj_id}")
        assert obj_id is not None

        # check the ownership
        owner_info = self.dor_proxy.get_owner(obj_id)
        logger.info(f"owner_info={owner_info}")
        assert owner_info['owner_iid'] == owner0.id()

        # perform TRANSFER w/ non-owner auth key
        reply = self.dor_proxy.transfer_ownership(obj_id, self.extras[2].signing_key(), owner1)
        assert reply is None

        # perform TRANSFER
        reply = self.dor_proxy.transfer_ownership(obj_id, owner0_k.signing_key(), owner1)
        logger.info(f"reply={reply}")
        assert reply is not None
        assert obj_id in reply
        assert reply[obj_id] == owner1.id()

        # check the ownership
        owner_info = self.dor_proxy.get_owner(obj_id)
        logger.info(f"owner_info={owner_info}")
        assert owner_info['owner_iid'] == owner1.id()

        # perform DELETE w/ wrong owner
        descriptor = self.dor_proxy.delete_data_object(obj_id, owner0_k.signing_key())
        logger.info(f"descriptor={descriptor}")
        assert descriptor is None

        # perform DELETE w/ correct owner
        descriptor = self.dor_proxy.delete_data_object(obj_id, owner1_k.signing_key())
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
        assert reply is None
        assert not os.path.exists(destination)

        reply = self.dor_proxy.get_content(obj_id, self.extras[1].signing_key(), destination)
        assert reply is not None
        assert reply == destination
        assert os.path.isfile(destination)

        descriptor2 = self.dor_proxy.delete_data_object(obj_id, self.extras[1].signing_key())
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_content_encryption(self):
        # create content for the data object and encrypt it
        content_plain = "my little secret..."
        content_enc, content_key = symmetric_encrypt(content_plain.encode('utf-8'))
        logger.info(f"content_plain={content_plain}")
        logger.info(f"content_enc={content_enc}")
        logger.info(f"content_key={content_key}")
        content_enc_path = self.create_file_with_content('content.enc', content_enc.decode('utf-8'))

        # add data object with the encrypted content
        owner_k1 = self.extras[1]
        owner1 = self.extras[1].identity()
        protected_content_key1 = owner1.encryption_public_key().encrypt(
            content_key, base64_encoded=True).decode('utf-8')
        obj_id, descriptor = self.dor_proxy.add_data_object(content_enc_path, owner1,
                                                            False, True, protected_content_key1,
                                                            'map', 'json', owner1.name())
        assert obj_id is not None
        assert descriptor is not None
        logger.info(f"descriptor={descriptor}")

        # transfer ownership now
        owner_k2 = self.extras[2]
        owner2 = self.extras[2].identity()
        protected_content_key2 = owner2.encryption_public_key().encrypt(
            content_key, base64_encoded=True).decode('utf-8')
        self.dor_proxy.transfer_ownership(obj_id, owner_k1.signing_key(), owner2, protected_content_key2)

        # we should be able to use this content key to decrypt the content
        unprotected_content_key = owner_k2.encryption_key().decrypt(protected_content_key2.encode('utf-8'),
                                                                    base64_encoded=True)
        unprotected_content = symmetric_decrypt(content_enc, unprotected_content_key).decode('utf-8')
        assert(unprotected_content == content_plain)

        descriptor = self.dor_proxy.delete_data_object(obj_id, owner_k2.signing_key())
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
        tags = self.dor_proxy.update_tags(obj_id, self.extras[1].signing_key(), {
            'a': '123',
            'b': '567'
        })
        logger.info(f"tags={tags}")
        assert len(tags) == 2
        assert 'a' in tags
        assert 'b' in tags
        assert tags['a'] == '123'

        # update tags for that data object
        tags = self.dor_proxy.update_tags(obj_id, self.extras[1].signing_key(), {
            'a': '567'
        })
        logger.info(f"tags={tags}")
        assert len(tags) == 2
        assert 'a' in tags
        assert 'b' in tags
        assert tags['a'] == '567'

        # remove a tag
        tags = self.dor_proxy.remove_tags(obj_id, self.extras[1].signing_key(), ['b'])
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
        test_file_path2 = self.generate_random_file('test002.dat', 1024*1024)

        # create the data object 0
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

        # create the data object 2
        obj_id2, _ = self.dor_proxy.add_data_object(test_file_path2, self.extras[2].identity(),
                                                    False, False, None,
                                                    data_type, data_format, created_by, created_t)
        logger.info(f"obj_id2: {obj_id2}")
        assert obj_id2 is not None

        # update tags for that data object
        self.dor_proxy.update_tags(obj_id2, self.extras[2].signing_key(), {
            'hello': '789',
            'world': '5675',
            'a': '56756'
        })
        tags2 = self.dor_proxy.get_tags(obj_id2)
        logger.info(f"tags2={tags2}")
        assert len(tags2) == 3

        # search for data objects
        result = self.dor_proxy.search(["hellox"])
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id0 in result

        result = self.dor_proxy.search(["hello"])
        logger.info(f"result={result}")
        assert len(result) == 3
        assert obj_id0 in result
        assert obj_id1 in result
        assert obj_id2 in result

        # the case where the owner is restricted
        result = self.dor_proxy.search(["hello"], owner_iid=self.extras[2].identity().id())
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id2 in result

        result = self.dor_proxy.search(["o"])
        logger.info(f"result={result}")
        assert len(result) == 3
        assert obj_id0 in result
        assert obj_id1 in result
        assert obj_id2 in result

        result = self.dor_proxy.search(["whazzup", "124"])
        logger.info(f"result={result}")
        assert len(result) == 2
        assert obj_id0 in result
        assert obj_id1 in result

        # delete the data object 0
        descriptor0 = self.dor_proxy.delete_data_object(obj_id0, self.extras[1].signing_key())
        logger.info(f"descriptor0={descriptor0}")
        assert descriptor0 is not None

        # delete the data object 1
        descriptor1 = self.dor_proxy.delete_data_object(obj_id1, self.extras[1].signing_key())
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        # delete the data object 2
        descriptor2 = self.dor_proxy.delete_data_object(obj_id2, self.extras[2].signing_key())
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None

        tags0 = self.dor_proxy.get_tags(obj_id0)
        logger.info(f"tags0={tags0}")
        assert len(tags0) == 0

        tags1 = self.dor_proxy.get_tags(obj_id1)
        logger.info(f"tags1={tags1}")
        assert len(tags1) == 0

        tags2 = self.dor_proxy.get_tags(obj_id2)
        logger.info(f"tags2={tags2}")
        assert len(tags2) == 0


if __name__ == '__main__':
    unittest.main()
