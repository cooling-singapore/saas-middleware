import json
import random
import shutil
import time
import unittest
import logging
import os

from saascore.api.sdk.exceptions import UnsuccessfulRequestError
from saascore.api.sdk.proxies import DORProxy, NodeDBProxy
from saascore.cryptography.helpers import symmetric_encrypt, symmetric_decrypt
from saascore.keystore.assets.credentials import CredentialsAsset, GithubCredentials
from saascore.log import Logging

from saas.dor.exceptions import FetchDataObjectFailedError
from saas.dor.schemas import Tag
from tests.base_testcase import TestCaseBase
from saascore.helpers import generate_random_string, get_timestamp_now
from saas.dor.protocol import DataObjectRepositoryP2PProtocol

Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


class DORRESTTestCase(unittest.TestCase, TestCaseBase):
    _wd_path = os.path.join(os.environ['HOME'], 'testing', str(get_timestamp_now()))
    _node = None
    _dor = None
    _unknown_user = None
    _known_user0 = None
    _known_user1 = None

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

        if DORRESTTestCase._node is None:
            DORRESTTestCase._node = self.get_node('node', enable_rest=True, keep_track=False,
                                                  wd_path=DORRESTTestCase._wd_path)
            DORRESTTestCase._dor = DORProxy(DORRESTTestCase._node.rest.address())

            extras = self.create_keystores(3)
            DORRESTTestCase._unknown_user = extras[0]
            DORRESTTestCase._known_user0 = extras[1]
            DORRESTTestCase._known_user1 = extras[2]

            DORRESTTestCase._node.db.update_identity(DORRESTTestCase._known_user0.identity)
            DORRESTTestCase._node.db.update_identity(DORRESTTestCase._known_user1.identity)

            time.sleep(1)

    def tearDown(self):
        self.cleanup()

    def test_rest_search(self):
        meta0 = self._node.db.add_data_object('foobaa0', None, 'data_type', 'data_format', 'created_by', None,
                                              self._node.identity, False, False)
        obj_id0 = meta0['obj_id']
        self._node.db.update_tags(obj_id0, [
            Tag(key='aaa', value='bbb')
        ])

        meta1 = self._node.db.add_data_object('foobaa1', None, 'data_type', 'data_format', 'created_by', None,
                                              self._node.identity, False, False)
        obj_id1 = meta1['obj_id']
        self._node.db.update_tags(obj_id1, [
            Tag(key='ccc', value='ddd')
        ])

        result = self._dor.search()
        print(result)
        assert(result is not None)

        result = self._dor.search(patterns=['aaa'])
        print(result)
        assert(result is not None)
        assert(len(result) == 1)

        result = self._dor.search(patterns=['zzz'])
        print(result)
        assert(result is not None)
        assert(len(result) == 0)

    def test_rest_statistics(self):
        result = self._dor.statistics()
        print(result)
        assert(result is not None)

    def test_rest_add(self):
        owner = self._node.identity

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, owner, False, False, 'JSON', 'json', owner.name)
        print(result)
        assert(result is not None)
        assert('obj_id' in result)

    def test_rest_add_gpp(self):
        owner = self._node.identity

        source = 'https://github.com/cooling-singapore/saas-middleware-sdk'
        commit_id = '9bf18c3'
        proc_path = 'saasadapters/example'
        proc_config = 'default'

        asset: CredentialsAsset = self._node.keystore.get_asset('github-credentials')
        github_credentials: GithubCredentials = asset.get(source)

        result = self._dor.add_gpp_data_object(source, commit_id, proc_path, proc_config, owner, owner.name,
                                               github_credentials=github_credentials)

        print(result)
        assert(result is not None)
        assert('obj_id' in result)

    def test_rest_delete(self):
        owner = self._node.identity

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = DORRESTTestCase._dor.add_data_object(content_path, owner, False, False, 'JSON', 'json', owner.name)
        print(result)
        assert(result is not None)
        assert('obj_id' in result)
        obj_id = result['obj_id']

        result = DORRESTTestCase._dor.delete_data_object(obj_id, with_authorisation_by=self._node.keystore)
        print(result)
        assert(result is not None)

        result = DORRESTTestCase._dor.get_meta(obj_id)
        print(result)
        assert(result is None)

    def test_rest_get_meta(self):
        owner = self._node.identity

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, owner, False, False, 'JSON', 'json', owner.name)
        valid_obj_id = result['obj_id']
        invalid_obj_id = 'invalid_obj_id'

        result = self._dor.get_meta(invalid_obj_id)
        assert(result is None)

        result = self._dor.get_meta(valid_obj_id)
        assert(result is not None)
        assert(result['obj_id'] == valid_obj_id)

    def test_rest_get_content(self):
        owner = self._node.identity

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, owner, False, False, 'JSON', 'json', owner.name)
        valid_obj_id = result['obj_id']
        invalid_obj_id = 'invalid_obj_id'

        download_path = os.path.join(self.wd_path, 'downloaded.json')

        correct_authority = self._node.keystore
        unknown_authority = self._unknown_user
        wrong_authority = self._known_user0

        try:
            self._dor.get_content(invalid_obj_id, correct_authority, download_path)
            assert False

        except UnsuccessfulRequestError as e:
            assert(e.details['reason'] == 'data object does not exist')

        try:
            self._dor.get_content(valid_obj_id, unknown_authority, download_path)
            assert False

        except UnsuccessfulRequestError as e:
            assert(e.details['reason'] == 'unknown identity')

        try:
            self._dor.get_content(valid_obj_id, wrong_authority, download_path)
            assert False

        except UnsuccessfulRequestError as e:
            assert(e.details['reason'] == 'user has no access to the data object content')

        try:
            result = self._dor.get_content(valid_obj_id, correct_authority, download_path)
            print(result)
            assert(os.path.isfile(download_path))

        except UnsuccessfulRequestError:
            assert False

    def test_rest_grant_revoke_access(self):
        owner = self._node.keystore

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, owner.identity, False, False, 'JSON', 'json',
                                           owner.identity.name)
        obj_id = result['obj_id']

        user0 = self._known_user0
        user1 = self._known_user1

        meta = self._dor.get_meta(obj_id)
        assert(owner.identity.id == meta['owner_iid'])
        assert(owner.identity.id in meta['access'])
        assert(user0.identity.id not in meta['access'])
        assert(user1.identity.id not in meta['access'])

        # try to grant access to a user that doesn't have access yet without being the owner
        try:
            self._dor.grant_access(obj_id, user0, user1.identity)
            assert False

        except UnsuccessfulRequestError as e:
            assert(e.details['reason'] == 'user is not the data object owner')

        # try to grant access to a user that doesn't have access yet
        try:
            meta = self._dor.grant_access(obj_id, owner, user1.identity)
            assert (owner.identity.id == meta['owner_iid'])
            assert (owner.identity.id in meta['access'])
            assert (user0.identity.id not in meta['access'])
            assert (user1.identity.id in meta['access'])

        except UnsuccessfulRequestError:
            assert False

        # try to grant access to a user that already has access
        try:
            meta = self._dor.grant_access(obj_id, owner, user1.identity)
            assert (owner.identity.id == meta['owner_iid'])
            assert (owner.identity.id in meta['access'])
            assert (user0.identity.id not in meta['access'])
            assert (user1.identity.id in meta['access'])

        except UnsuccessfulRequestError:
            assert False

        # try to revoke access form a user that has access without being the owner
        try:
            self._dor.revoke_access(obj_id, user0, user1.identity)
            assert False

        except UnsuccessfulRequestError as e:
            assert(e.details['reason'] == 'user is not the data object owner')

        # try to revoke access form a user that has access
        try:
            meta = self._dor.revoke_access(obj_id, owner, user1.identity)
            assert (owner.identity.id == meta['owner_iid'])
            assert (owner.identity.id in meta['access'])
            assert (user0.identity.id not in meta['access'])
            assert (user1.identity.id not in meta['access'])

        except UnsuccessfulRequestError:
            assert False

        # try to revoke access form a user that doesn't have access
        try:
            meta = self._dor.revoke_access(obj_id, owner, user0.identity)
            assert (owner.identity.id == meta['owner_iid'])
            assert (owner.identity.id in meta['access'])
            assert (user0.identity.id not in meta['access'])
            assert (user1.identity.id not in meta['access'])

        except UnsuccessfulRequestError:
            assert False

    def test_rest_transfer_ownership(self):
        owner = self._node.keystore

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, owner.identity, False, False, 'JSON', 'json',
                                           owner.identity.name)
        obj_id = result['obj_id']

        user0 = self._known_user0
        user1 = self._known_user1
        user2 = self._unknown_user

        meta = self._dor.get_meta(obj_id)
        assert(owner.identity.id == meta['owner_iid'])

        # try to transfer ownership without being the owner
        try:
            self._dor.transfer_ownership(obj_id, user0, user1.identity)
            assert False

        except UnsuccessfulRequestError as e:
            assert(e.details['reason'] == 'user is not the data object owner')

        # try to transfer ownership to an unknown user
        try:
            self._dor.transfer_ownership(obj_id, owner, user2.identity)
            assert False

        except UnsuccessfulRequestError as e:
            assert('Identity not found' in e.reason)

        # try to transfer ownership to a known user
        try:
            meta = self._dor.transfer_ownership(obj_id, owner, user0.identity)
            assert (user0.identity.id == meta['owner_iid'])

        except UnsuccessfulRequestError:
            assert False

    def test_rest_update_remove_tags(self):
        owner = self._node.keystore

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, owner.identity, False, False, 'JSON', 'json',
                                           owner.identity.name)
        obj_id = result['obj_id']

        wrong_user = self._known_user0

        meta = self._dor.get_meta(obj_id)
        assert(owner.identity.id == meta['owner_iid'])
        assert(len(meta['tags']) == 0)

        # try to set tags by non-owner
        try:
            self._dor.update_tags(obj_id, wrong_user, {'name': 'abc'})

        except UnsuccessfulRequestError as e:
            assert (e.details['reason'] == 'user is not the data object owner')

        # try to set tags by owner
        try:
            meta = self._dor.update_tags(obj_id, owner, {'name': 'abc'})
            assert(len(meta['tags']) == 1)
            assert(meta['tags'][0]['key'] == 'name')
            assert(meta['tags'][0]['value'] == 'abc')

        except UnsuccessfulRequestError as e:
            assert False

        # try to set tags by owner
        try:
            meta = self._dor.update_tags(obj_id, owner, {'name': 'bcd'})
            assert(len(meta['tags']) == 1)
            assert(meta['tags'][0]['key'] == 'name')
            assert(meta['tags'][0]['value'] == 'bcd')

        except UnsuccessfulRequestError as e:
            assert False

        # try to remove existing tag by non-owner
        try:
            self._dor.remove_tags(obj_id, wrong_user, ['name'])
            assert False

        except UnsuccessfulRequestError as e:
            assert (e.details['reason'] == 'user is not the data object owner')

        # try to remove non-existing tag by owner
        try:
            self._dor.remove_tags(obj_id, owner, ['invalid_key'])

        except UnsuccessfulRequestError as e:
            assert False

        # try to remove existing tag by owner
        try:
            meta = self._dor.remove_tags(obj_id, owner, ['name'])
            assert (len(meta['tags']) == 0)

        except UnsuccessfulRequestError:
            assert False


class DORServiceTestCase(unittest.TestCase, TestCaseBase):
    _wd_path = os.path.join(os.environ['HOME'], 'testing', str(get_timestamp_now()))
    _node = None
    _dor = None
    _db = None
    _unknown_user = None
    _known_user0 = None
    _known_user1 = None

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

        if DORServiceTestCase._node is None:
            DORServiceTestCase._node = self.get_node('node', enable_rest=True, keep_track=False,
                                                     wd_path=DORServiceTestCase._wd_path)
            DORServiceTestCase._dor = DORProxy(DORServiceTestCase._node.rest.address())
            DORServiceTestCase._db = NodeDBProxy(DORServiceTestCase._node.rest.address())

            extras = self.create_keystores(3)
            DORServiceTestCase._unknown_user = extras[0]
            DORServiceTestCase._known_user0 = extras[1]
            DORServiceTestCase._known_user1 = extras[2]

            DORServiceTestCase._node.db.update_identity(DORServiceTestCase._known_user0.identity)
            DORServiceTestCase._node.db.update_identity(DORServiceTestCase._known_user1.identity)

            time.sleep(1)

    def tearDown(self):
        self.cleanup()

    def test_content_encryption(self):
        # create content for the data object and encrypt it
        content_plain = "my little secret..."
        content_enc, content_key = symmetric_encrypt(content_plain.encode('utf-8'))
        logger.info(f"content_plain={content_plain}")
        logger.info(f"content_enc={content_enc}")
        logger.info(f"content_key={content_key}")
        content_enc_path = self.create_file_with_content('content.enc', content_enc.decode('utf-8'))

        owner1 = self._known_user0
        owner2 = self._known_user1

        # add data object with the encrypted content
        protected_content_key1 = owner1.encrypt(content_key).decode('utf-8')
        meta = self._dor.add_data_object(content_enc_path, owner1.identity, False, True, 'map', 'json',
                                         owner1.identity.name)
        obj_id = meta['obj_id']

        # transfer ownership now
        protected_content_key2 = owner2.encrypt(content_key).decode('utf-8')
        self._dor.transfer_ownership(obj_id, owner1, owner2.identity)

        # we should be able to use the content key to decrypt the content
        unprotected_content_key = owner2.decrypt(protected_content_key2.encode('utf-8'))
        unprotected_content = symmetric_decrypt(content_enc, unprotected_content_key).decode('utf-8')
        assert(unprotected_content == content_plain)

        self._dor.delete_data_object(obj_id, owner2)

    def test_fetch_data_object(self):
        owner = self._known_user0
        meta = self._dor.add_data_object(self.generate_zero_file('test000.dat', 1024*1024),
                                         owner.identity, True, False, 'map', 'json', owner.identity.name)
        obj_id = meta['obj_id']

        # create the receiving node
        receiver = self.get_node('receiver')
        receiver_identity = receiver.update_identity()
        self._db.update_identity(receiver_identity)

        protocol = DataObjectRepositoryP2PProtocol(receiver)

        # try to fetch a data object that doesn't exist
        fake_obj_id = 'abcdef'
        meta_path = os.path.join(self.wd_path, f"{fake_obj_id}.meta")
        content_path = os.path.join(self.wd_path, f"{fake_obj_id}.content")
        try:
            protocol.fetch(self._node.p2p.address(), fake_obj_id,
                           destination_meta_path=meta_path,
                           destination_content_path=content_path)
            assert False

        except FetchDataObjectFailedError:
            assert True

        # the receiver does not have permission at this point to receive the data object
        meta_path = os.path.join(self.wd_path, f"{obj_id}.meta")
        content_path = os.path.join(self.wd_path, f"{obj_id}.content")
        try:
            protocol.fetch(self._node.p2p.address(), obj_id,
                           destination_meta_path=meta_path,
                           destination_content_path=content_path)
            assert False

        except FetchDataObjectFailedError:
            assert True

        # grant permission
        meta = self._dor.grant_access(obj_id, owner, receiver_identity)
        assert receiver_identity.id in meta['access']

        # create user signature to delegate access rights
        token = f"{receiver_identity.id}:{obj_id}"
        signature = receiver.keystore.sign(token.encode('utf-8'))

        # the receiver does have permission at this point to receive the data object
        protocol.fetch(self._node.p2p.address(), obj_id,
                       destination_meta_path=meta_path,
                       destination_content_path=content_path,
                       user_signature=signature, user_iid=receiver_identity.id)
        assert os.path.isfile(meta_path)
        assert os.path.isfile(content_path)

        self._dor.delete_data_object(obj_id, owner)

    def test_search_by_content_hashes(self):
        owner = self._known_user0

        # create data objects
        meta0 = self._dor.add_data_object(self.generate_random_file(generate_random_string(4), 1024*1024),
                                          owner.identity, False, False, 'map', 'json', owner.identity.name)
        meta1 = self._dor.add_data_object(self.generate_random_file(generate_random_string(4), 1024*1024),
                                          owner.identity, False, False, 'map', 'json', owner.identity.name)
        meta2 = self._dor.add_data_object(self.generate_random_file(generate_random_string(4), 1024*1024),
                                          owner.identity, False, False, 'map', 'json', owner.identity.name)
        obj_id0 = meta0['obj_id']
        obj_id1 = meta1['obj_id']
        obj_id2 = meta2['obj_id']
        c_hash0 = meta0['c_hash']
        c_hash1 = meta1['c_hash']
        c_hash2 = meta2['c_hash']

        # search for data objects
        result = self._dor.search(c_hashes=[c_hash0, c_hash1])
        logger.info(f"result={result}")
        assert len(result) == 2
        result = {i['obj_id']: i['tags'] for i in result}
        assert obj_id0 in result
        assert obj_id1 in result

        # search for data objects
        result = self._dor.search(c_hashes=[c_hash2])
        logger.info(f"result={result}")
        assert len(result) == 1
        result = {i['obj_id']: i['tags'] for i in result}
        assert obj_id2 in result

        self._dor.delete_data_object(obj_id0, owner)
        self._dor.delete_data_object(obj_id1, owner)
        self._dor.delete_data_object(obj_id2, owner)


if __name__ == '__main__':
    unittest.main()
