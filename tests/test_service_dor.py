import unittest
import logging
import os

from saas.cryptography.helpers import symmetric_encrypt, symmetric_decrypt
from saas.dor.blueprint import DORProxy
from saas.dor.exceptions import FetchDataObjectFailedError
from saas.nodedb.blueprint import NodeDBProxy
from saas.rest.exceptions import UnsuccessfulRequestError
from tests.base_testcase import TestCaseBase
from saas.helpers import object_to_ordered_list, generate_random_string
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
            identity = extra.update_profile()
            self.db_proxy.update_identity(identity)

    def tearDown(self):
        self.cleanup()

    def test_add_delete_data_object(self):
        owner = self.extras[0].identity
        meta = self.dor_proxy.add_data_object(self.generate_zero_file('test000.dat', 1024*1024), owner,
                                              False, False, 'map', 'json', owner.name)
        assert meta is not None
        obj_id = meta['obj_id']

        # get the descriptor of the data object
        meta1 = self.dor_proxy.get_meta(obj_id)
        logger.info(f"meta1={meta1}")
        assert meta1 is not None

        # delete the data object
        meta2 = self.dor_proxy.delete_data_object(obj_id, self.extras[0])
        logger.info(f"meta2={meta2}")
        assert meta2 is not None
        assert object_to_ordered_list(meta1) == object_to_ordered_list(meta2)

    def test_add_delete_gpp_data_object(self):
        source = 'https://github.com/cooling-singapore/saas-processor-template'
        commit_id = '972bd54'
        proc_path = 'processor_test'
        proc_config = 'default'

        # create the data object
        owner = self.extras[0].identity
        meta = self.dor_proxy.add_gpp_data_object(source, commit_id, proc_path, proc_config, owner, owner.name)
        assert meta is not None
        obj_id = meta['obj_id']

        # get the descriptor of the data object
        meta1 = self.dor_proxy.get_meta(obj_id)
        logger.info(f"descriptor1={meta1}")
        assert meta1 is not None
        assert('gpp' in meta1)
        assert('proc_descriptor' in meta1['gpp'])

        # delete the data object
        meta2 = self.dor_proxy.delete_data_object(obj_id, self.extras[0])
        logger.info(f"meta2={meta2}")
        assert meta2 is not None
        assert object_to_ordered_list(meta1) == object_to_ordered_list(meta2)

    def test_grant_revoke_access(self):
        owner = self.extras[1].identity
        meta = self.dor_proxy.add_data_object(self.generate_zero_file('test000.dat', 1024*1024),
                                              owner, False, False, 'map', 'json', owner.name)
        obj_id = meta['obj_id']

        assert len(meta['access']) == 1

        try:
            self.dor_proxy.grant_access(obj_id, self.extras[0], self.extras[2].identity)
            assert False

        except UnsuccessfulRequestError:
            assert True

        meta = self.dor_proxy.get_meta(obj_id)
        assert len(meta['access']) == 1

        meta = self.dor_proxy.grant_access(obj_id, self.extras[1], self.extras[2].identity)
        assert self.extras[2].identity.id in meta['access']

        meta = self.dor_proxy.get_meta(obj_id)
        assert len(meta['access']) == 2
        assert self.extras[2].identity.id in meta['access']

        meta = self.dor_proxy.revoke_access(obj_id, self.extras[1], self.extras[2].identity)
        assert self.extras[2].identity.id not in meta['access']

        meta = self.dor_proxy.get_meta(obj_id)
        assert len(meta['access']) == 1

        meta = self.dor_proxy.delete_data_object(obj_id, self.extras[1])
        assert meta is not None

    def test_transfer_ownership(self):
        owner0_k = self.extras[0]
        owner0 = owner0_k.update_profile(name="User0", email=self.node.identity().email)
        self.db_proxy.update_identity(owner0)

        owner1_k = self.extras[1]
        owner1 = owner1_k.update_profile(name="User1", email=self.node.identity().email)
        self.db_proxy.update_identity(owner1)

        meta = self.dor_proxy.add_data_object(self.generate_zero_file('test000.dat', 1024*1024),
                                              owner0, False, False, 'map', 'json', owner0.name)
        obj_id = meta['obj_id']

        # check the ownership
        assert meta['owner_iid'] == owner0.id

        # perform TRANSFER w/ non-owner auth key
        try:
            self.dor_proxy.transfer_ownership(obj_id, self.extras[2], owner1)
            assert False

        except UnsuccessfulRequestError:
            assert True

        # perform TRANSFER
        meta = self.dor_proxy.transfer_ownership(obj_id, owner0_k, owner1)
        assert meta['owner_iid'] == owner1.id

        # check the ownership
        meta = self.dor_proxy.get_meta(obj_id)
        assert meta['owner_iid'] == owner1.id

        # perform DELETE w/ wrong owner
        try:
            self.dor_proxy.delete_data_object(obj_id, owner0_k)
            assert False

        except UnsuccessfulRequestError:
            assert True

        # perform DELETE w/ correct owner
        self.dor_proxy.delete_data_object(obj_id, owner1_k)

    def test_get_content(self):
        owner = self.extras[1]
        user = self.extras[2]
        meta = self.dor_proxy.add_data_object(self.generate_zero_file('test000.dat', 1024*1024),
                                              owner.identity, True, False, 'map', 'json', owner.identity.name)
        obj_id = meta['obj_id']
        destination = os.path.join(self.wd_path, 'test_copy.dat')

        # the OWNER can get content
        try:
            self.dor_proxy.get_content(obj_id, owner, destination)
            assert True

        except UnsuccessfulRequestError:
            assert False

        # the USER has NO ACCESS yet and cannot get content
        try:
            self.dor_proxy.get_content(obj_id, user, destination)
            assert False

        except UnsuccessfulRequestError:
            assert True

        self.dor_proxy.grant_access(obj_id, owner, user.identity)

        # the USER has ACCESS and can get content
        try:
            self.dor_proxy.get_content(obj_id, user, destination)
            assert True

        except UnsuccessfulRequestError:
            assert False

        self.dor_proxy.delete_data_object(obj_id, owner)

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
        owner1 = self.extras[1].identity
        protected_content_key1 = owner1.encrypt(content_key).decode('utf-8')
        meta = self.dor_proxy.add_data_object(content_enc_path, owner1, False, True, 'map', 'json', owner1.name)
        obj_id = meta['obj_id']

        # transfer ownership now
        owner_k2 = self.extras[2]
        owner2 = self.extras[2].identity
        protected_content_key2 = owner2.encrypt(content_key).decode('utf-8')
        self.dor_proxy.transfer_ownership(obj_id, owner_k1, owner2)

        # we should be able to use this content key to decrypt the content
        unprotected_content_key = owner_k2.decrypt(protected_content_key2.encode('utf-8'))
        unprotected_content = symmetric_decrypt(content_enc, unprotected_content_key).decode('utf-8')
        assert(unprotected_content == content_plain)

        self.dor_proxy.delete_data_object(obj_id, owner_k2)

    def test_fetch_data_object(self):
        owner = self.extras[1].identity
        meta = self.dor_proxy.add_data_object(self.generate_zero_file('test000.dat', 1024*1024),
                                              owner, True, False, 'map', 'json', owner.name)
        obj_id = meta['obj_id']

        # create the receiving node
        receiver = self.get_node('receiver')
        receiver_identity = receiver.update_identity()
        self.db_proxy.update_identity(receiver_identity)

        protocol = DataObjectRepositoryP2PProtocol(receiver)

        # try to fetch a data object that doesn't exist
        fake_obj_id = 'abcdef'
        meta_path = os.path.join(self.wd_path, f"{fake_obj_id}.meta")
        content_path = os.path.join(self.wd_path, f"{fake_obj_id}.content")
        try:
            protocol.fetch(self.node.p2p.address(), fake_obj_id,
                           destination_meta_path=meta_path,
                           destination_content_path=content_path)
            assert False

        except FetchDataObjectFailedError:
            assert True

        # the receiver does not have permission at this point to receive the data object
        meta_path = os.path.join(self.wd_path, f"{obj_id}.meta")
        content_path = os.path.join(self.wd_path, f"{obj_id}.content")
        try:
            protocol.fetch(self.node.p2p.address(), obj_id,
                           destination_meta_path=meta_path,
                           destination_content_path=content_path)
            assert False

        except FetchDataObjectFailedError:
            assert True

        # grant permission
        meta = self.dor_proxy.grant_access(obj_id, self.extras[1], receiver_identity)
        assert receiver_identity.id in meta['access']

        # create user signature to delegate access rights
        token = f"{receiver_identity.id}:{obj_id}"
        signature = receiver.keystore.sign(token.encode('utf-8'))

        # the receiver does have permission at this point to receive the data object
        protocol.fetch(self.node.p2p.address(), obj_id,
                       destination_meta_path=meta_path,
                       destination_content_path=content_path,
                       user_signature=signature, user_iid=receiver_identity.id)
        assert os.path.isfile(meta_path)
        assert os.path.isfile(content_path)

        self.dor_proxy.delete_data_object(obj_id, self.extras[1])

    def test_add_tag_delete_data_object(self):
        owner = self.extras[1].identity
        meta = self.dor_proxy.add_data_object(self.generate_zero_file('test000.dat', 1024*1024),
                                              owner, False, False, 'map', 'json', owner.name)
        obj_id = meta['obj_id']

        assert len(meta['tags']) == 0

        # update tags for that data object
        meta = self.dor_proxy.update_tags(obj_id, self.extras[1], {
            'a': '123',
            'b': '567'
        })
        assert len(meta['tags']) == 2
        tags = {tag['key']: tag['value'] for tag in meta['tags']}
        assert 'a' in tags
        assert 'b' in tags
        assert tags['a'] == '123'

        # update tags for that data object
        meta = self.dor_proxy.update_tags(obj_id, self.extras[1], {
            'a': '567'
        })
        assert len(meta['tags']) == 2
        tags = {tag['key']: tag['value'] for tag in meta['tags']}
        assert 'a' in tags
        assert 'b' in tags
        assert tags['a'] == '567'

        # remove a tag
        meta = self.dor_proxy.remove_tags(obj_id, self.extras[1], ['b'])
        assert len(meta['tags']) == 1
        tags = {tag['key']: tag['value'] for tag in meta['tags']}
        assert 'a' in tags
        assert 'b' not in tags

        # delete the data object
        self.dor_proxy.delete_data_object(obj_id, self.extras[1])

    def test_add_tag_search_delete_data_object(self):
        owner1 = self.extras[1].identity
        owner2 = self.extras[2].identity

        # create the data object 0
        meta0 = self.dor_proxy.add_data_object(self.generate_zero_file('test000.dat', 1024*1024),
                                               owner1, False, False, 'map', 'json', owner1.name)
        obj_id0 = meta0['obj_id']

        # update tags for that data object
        meta0 = self.dor_proxy.update_tags(obj_id0, self.extras[1], {
            'hellox': '123',
            'whazzup': '567',
            'a': '123'
        })
        assert len(meta0['tags']) == 3

        # create the data object 1
        meta1 = self.dor_proxy.add_data_object(self.generate_zero_file('test000.dat', 1024*1024),
                                               owner1, False, False, 'map', 'json', owner1.name)
        obj_id1 = meta1['obj_id']

        # update tags for that data object
        meta1 = self.dor_proxy.update_tags(obj_id1, self.extras[1], {
            'hello': '123',
            'world': '567',
            'a': '124'
        })
        assert len(meta1['tags']) == 3

        # create the data object 2
        meta2 = self.dor_proxy.add_data_object(self.generate_zero_file('test000.dat', 1024*1024),
                                               owner2, False, False, 'map', 'json', owner2.name)
        obj_id2 = meta2['obj_id']

        # update tags for that data object
        meta2 = self.dor_proxy.update_tags(obj_id2, self.extras[2], {
            'hello': '789',
            'world': '5675',
            'a': '56756'
        })
        assert len(meta2['tags']) == 3

        # search for data objects
        result = self.dor_proxy.search(["hellox"])
        logger.info(f"result={result}")
        assert len(result) == 1
        result = {i['obj_id']: i['tags'] for i in result}
        assert obj_id0 in result

        result = self.dor_proxy.search(["hello"])
        logger.info(f"result={result}")
        assert len(result) == 3
        result = {i['obj_id']: i['tags'] for i in result}
        assert obj_id0 in result
        assert obj_id1 in result
        assert obj_id2 in result

        # the case where the owner is restricted
        result = self.dor_proxy.search(["hello"], owner_iid=owner2.id)
        logger.info(f"result={result}")
        assert len(result) == 1
        result = {i['obj_id']: i['tags'] for i in result}
        assert obj_id2 in result

        result = self.dor_proxy.search(["o"])
        logger.info(f"result={result}")
        assert len(result) == 3
        result = {i['obj_id']: i['tags'] for i in result}
        assert obj_id0 in result
        assert obj_id1 in result
        assert obj_id2 in result

        result = self.dor_proxy.search(["whazzup", "124"])
        logger.info(f"result={result}")
        assert len(result) == 2

        result = self.dor_proxy.statistics()
        logger.info(f"statistics={result}")
        assert('json' in result['data_formats'])
        assert('map' in result['data_types'])
        assert(result['tag_keys'] == ['a', 'hello', 'world', 'hellox', 'whazzup'])

        self.dor_proxy.delete_data_object(obj_id0, self.extras[1])
        self.dor_proxy.delete_data_object(obj_id1, self.extras[1])
        self.dor_proxy.delete_data_object(obj_id2, self.extras[2])

    def test_search_by_content_hashes(self):
        owner = self.extras[1]

        # create data objects
        meta0 = self.dor_proxy.add_data_object(self.generate_random_file(generate_random_string(4), 1024*1024),
                                               owner.identity, False, False, 'map', 'json', owner.identity.name)
        meta1 = self.dor_proxy.add_data_object(self.generate_random_file(generate_random_string(4), 1024*1024),
                                               owner.identity, False, False, 'map', 'json', owner.identity.name)
        meta2 = self.dor_proxy.add_data_object(self.generate_random_file(generate_random_string(4), 1024*1024),
                                               owner.identity, False, False, 'map', 'json', owner.identity.name)
        obj_id0 = meta0['obj_id']
        obj_id1 = meta1['obj_id']
        obj_id2 = meta2['obj_id']
        c_hash0 = meta0['c_hash']
        c_hash1 = meta1['c_hash']
        c_hash2 = meta2['c_hash']

        # search for data objects
        result = self.dor_proxy.search(c_hashes=[c_hash0, c_hash1])
        logger.info(f"result={result}")
        assert len(result) == 2
        result = {i['obj_id']: i['tags'] for i in result}
        assert obj_id0 in result
        assert obj_id1 in result

        # search for data objects
        result = self.dor_proxy.search(c_hashes=[c_hash2])
        logger.info(f"result={result}")
        assert len(result) == 1
        result = {i['obj_id']: i['tags'] for i in result}
        assert obj_id2 in result

        self.dor_proxy.delete_data_object(obj_id0, owner)
        self.dor_proxy.delete_data_object(obj_id1, owner)
        self.dor_proxy.delete_data_object(obj_id2, owner)


if __name__ == '__main__':
    unittest.main()
