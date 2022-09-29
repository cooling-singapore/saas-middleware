import json
import random
import shutil
import time
import unittest
import logging
import os

from saas.cryptography.helpers import hash_json_object, symmetric_decrypt, symmetric_encrypt
from saas.dor.exceptions import FetchDataObjectFailedError
from saas.dor.proxy import DORProxy
from saas.exceptions import UnsuccessfulRequestError
from saas.helpers import get_timestamp_now, generate_random_string
from saas.keystore.assets.credentials import CredentialsAsset, GithubCredentials
from saas.log import Logging
from saas.nodedb.proxy import NodeDBProxy
from tests.base_testcase import TestCaseBase
from saas.dor.protocol import DataObjectRepositoryP2PProtocol

Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


class DORTestCase(unittest.TestCase, TestCaseBase):
    _wd_path = os.path.join(os.environ['HOME'], 'testing', str(get_timestamp_now()))
    _node = None
    _db = None
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

        if DORTestCase._node is None:
            DORTestCase._node = self.get_node('node', enable_rest=True, keep_track=False, wd_path=DORTestCase._wd_path)
            DORTestCase._db = NodeDBProxy(DORTestCase._node.rest.address())
            DORTestCase._dor = DORProxy(DORTestCase._node.rest.address())

            extras = self.create_keystores(3)
            DORTestCase._unknown_user = extras[0]
            DORTestCase._known_user0 = extras[1]
            DORTestCase._known_user1 = extras[2]

            DORTestCase._node.db.update_identity(DORTestCase._known_user0.identity)
            DORTestCase._node.db.update_identity(DORTestCase._known_user1.identity)

            time.sleep(1)

    def tearDown(self):
        self.cleanup()

    def test_search(self):
        result = self._dor.search()
        print(result)
        assert(result is not None)

    def test_statistics(self):
        result = self._dor.statistics()
        print(result)
        assert(result is not None)

    def test_add_c_multiple_creators(self):
        owner = self._node.identity

        c0 = self._known_user0
        c1 = self._known_user1

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, owner, False, False, 'JSON', 'json',
                                           [c0.identity, c1.identity])
        print(result)
        assert(result is not None)
        assert(len(result.created.creators_iid) == 2)
        assert(c0.identity.id in result.created.creators_iid)
        assert(c1.identity.id in result.created.creators_iid)

        result = self._dor.add_data_object(content_path, owner, False, False, 'JSON', 'json')
        print(result)
        assert(result is not None)
        assert(len(result.created.creators_iid) == 1)
        assert(owner.id in result.created.creators_iid)

    def test_add_c_license(self):
        owner = self._node.identity

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, owner, False, False, 'JSON', 'json', license_by=True)

        print(result)
        assert(result is not None)
        assert result.license.by
        assert(not result.license.sa)
        assert(not result.license.nc)
        assert(not result.license.nd)

    def test_add_c(self):
        owner = self._node.identity

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        # unknown owner
        try:
            self._dor.add_data_object(content_path, self._unknown_user.identity, False, False, 'JSON', 'json', [owner])
            assert False

        except UnsuccessfulRequestError as e:
            assert('Identity not found' in e.reason)

        # unknown creator
        try:
            self._dor.add_data_object(content_path, owner, False, False, 'JSON', 'json', [self._unknown_user.identity])
            assert False

        except UnsuccessfulRequestError as e:
            assert('Identity not found' in e.reason)

        result = self._dor.add_data_object(content_path, owner, False, False, 'JSON', 'json', [owner])
        print(result)
        assert(result is not None)

    def test_add_gpp(self):
        owner = self._node.identity

        source = 'https://github.com/cooling-singapore/saas-middleware-sdk'
        commit_id = '9bf18c3'
        proc_path = 'saasadapters/example'
        proc_config = 'default'

        asset: CredentialsAsset = self._node.keystore.get_asset('github-credentials')
        github_credentials: GithubCredentials = asset.get(source)

        result = self._dor.add_gpp_data_object(source, commit_id, proc_path, proc_config, owner,
                                               github_credentials=github_credentials)

        print(result)
        assert(result is not None)

    def test_remove(self):
        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, self._known_user0.identity, False, False, 'JSON', 'json')
        print(result)
        obj_id = result.obj_id

        # try to delete non-existent object
        try:
            self._dor.delete_data_object('invalid obj id', with_authorisation_by=self._known_user0)
            assert False

        except UnsuccessfulRequestError as e:
            assert('data object does not exist' in e.details['reason'])

        # try to delete with wrong authority
        try:
            self._dor.delete_data_object(obj_id, with_authorisation_by=self._known_user1)
            assert False

        except UnsuccessfulRequestError as e:
            assert ('user is not the data object owner' in e.details['reason'])

        # try to delete with correct authority
        try:
            result = self._dor.delete_data_object(obj_id, with_authorisation_by=self._known_user0)
            print(result)
            assert(result is not None)
            assert(result.obj_id == obj_id)

        except UnsuccessfulRequestError as e:
            assert ('' in e.reason)

        result = self._dor.get_meta(obj_id)
        print(result)
        assert(result is None)

    def test_get_meta(self):
        owner = self._node.identity

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, owner, False, False, 'JSON', 'json')
        valid_obj_id = result.obj_id
        invalid_obj_id = 'invalid_obj_id'

        result = self._dor.get_meta(invalid_obj_id)
        assert(result is None)

        result = self._dor.get_meta(valid_obj_id)
        assert(result is not None)
        assert(result.obj_id == valid_obj_id)

    def test_get_content(self):
        owner = self._node.identity

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, owner, False, False, 'JSON', 'json')
        valid_obj_id = result.obj_id
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

    def test_get_provenance(self):
        processor = {
            # 'c_hash': '0123456789abcdef',
            'source': 'github.com/source',
            'commit_id': '34534ab',
            'proc_path': '/proc',
            'proc_config': 'default',
            'proc_descriptor': {
                'name': 'proc0',
                'input': [{
                    'name': 'a',
                    'data_type': 'JSON',
                    'data_format': 'json',
                }, {
                    'name': 'b',
                    'data_type': 'JSON',
                    'data_format': 'json',
                }],
                'output': [{
                    'name': 'c',
                    'data_type': 'JSON',
                    'data_format': 'json',
                }],
                'configurations': ['default']
            }
        }

        owner = self._node.identity

        # create contents
        content_path_a = os.path.join(self.wd_path, 'a.json')
        content_path_c = os.path.join(self.wd_path, 'c.json')
        self.create_file_with_content(content_path_a, json.dumps({'v': 1}))
        self.create_file_with_content(content_path_c, json.dumps({'v': 3}))
        b_c_hash = hash_json_object({'v': 2}).hex()

        meta_a = self._dor.add_data_object(content_path_a, owner, False, False, 'JSON', 'json', recipe=None)
        result = self._dor.get_provenance(meta_a.c_hash)
        print(result)
        assert(result is not None)
        assert(meta_a.c_hash in result.data_nodes)
        assert(meta_a.c_hash in result.missing)

        meta_c = self._dor.add_data_object(content_path_c, owner, False, False, 'JSON', 'json', recipe={
            'processor': processor,
            'consumes': {
                'a': {
                    'c_hash': meta_a.c_hash,
                    'data_type': 'JSON',
                    'data_format': 'json'
                },
                'b': {
                    'c_hash': b_c_hash,
                    'data_type': 'JSON',
                    'data_format': 'json',
                    'content': {'v': 2}
                }
            },
            'product': {
                'c_hash': 'unknown',
                'data_type': 'JSON',
                'data_format': 'json'
            },
            'name': 'c'
        })

        result = self._dor.get_provenance(b_c_hash)
        print(result)
        assert(result is not None)

        result = self._dor.get_provenance(meta_c.c_hash)
        print(result)
        assert(result is not None)
        assert(len(result.steps) == 1)
        step = result.steps[0]
        assert(step.processor == '5e4871029fd3a88f72f43377223e7efc37aa5a579ad464c59c593695a40c79aa')
        assert(step.consumes['a'] == '9ab2253fc38981f5be9c25cf0a34b62cdf334652344bdef16b3d5dbc0b74f2f1')
        assert(step.consumes['b'] == '2b5442799fccc3af2e7e790017697373913b7afcac933d72fb5876de994f659a')
        assert(step.produces['c'] == 'b460644a73d5df6998c57c4eaf43ebc3e595bd06930af6e42d0008f84d91c849')

    def test_grant_revoke_access(self):
        owner = self._node.keystore

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, owner.identity, False, False, 'JSON', 'json')
        obj_id = result.obj_id

        user0 = self._known_user0
        user1 = self._known_user1

        meta = self._dor.get_meta(obj_id)
        assert(owner.identity.id == meta.owner_iid)
        assert(owner.identity.id in meta.access)
        assert(user0.identity.id not in meta.access)
        assert(user1.identity.id not in meta.access)

        # try to grant access to a user that doesn't have access yet without being the owner
        try:
            self._dor.grant_access(obj_id, user0, user1.identity)
            assert False

        except UnsuccessfulRequestError as e:
            assert(e.details['reason'] == 'user is not the data object owner')

        # try to grant access to a user that doesn't have access yet
        try:
            meta = self._dor.grant_access(obj_id, owner, user1.identity)
            assert (owner.identity.id == meta.owner_iid)
            assert (owner.identity.id in meta.access)
            assert (user0.identity.id not in meta.access)
            assert (user1.identity.id in meta.access)

        except UnsuccessfulRequestError:
            assert False

        # try to grant access to a user that already has access
        try:
            meta = self._dor.grant_access(obj_id, owner, user1.identity)
            assert (owner.identity.id == meta.owner_iid)
            assert (owner.identity.id in meta.access)
            assert (user0.identity.id not in meta.access)
            assert (user1.identity.id in meta.access)

        except UnsuccessfulRequestError:
            assert False

        # try to revoke access from a user that has access without being the owner
        try:
            self._dor.revoke_access(obj_id, user0, user1.identity)
            assert False

        except UnsuccessfulRequestError as e:
            assert(e.details['reason'] == 'user is not the data object owner')

        # try to revoke access from a user that has access
        try:
            meta = self._dor.revoke_access(obj_id, owner, user1.identity)
            assert (owner.identity.id == meta.owner_iid)
            assert (owner.identity.id in meta.access)
            assert (user0.identity.id not in meta.access)
            assert (user1.identity.id not in meta.access)

        except UnsuccessfulRequestError:
            assert False

        # try to revoke access from a user that doesn't have access
        try:
            meta = self._dor.revoke_access(obj_id, owner, user0.identity)
            assert (owner.identity.id == meta.owner_iid)
            assert (owner.identity.id in meta.access)
            assert (user0.identity.id not in meta.access)
            assert (user1.identity.id not in meta.access)

        except UnsuccessfulRequestError:
            assert False

    def test_transfer_ownership(self):
        owner = self._node.keystore

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        meta = self._dor.add_data_object(content_path, owner.identity, False, False, 'JSON', 'json')
        obj_id = meta.obj_id

        user0 = self._known_user0
        user1 = self._known_user1
        user2 = self._unknown_user

        meta = self._dor.get_meta(obj_id)
        assert(owner.identity.id == meta.owner_iid)

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
            assert (user0.identity.id == meta.owner_iid)

        except UnsuccessfulRequestError:
            assert False

    def test_update_remove_tags(self):
        owner = self._node.keystore

        # create content
        content_path = os.path.join(self.wd_path, 'test.json')
        with open(content_path, 'w') as f:
            f.write(json.dumps({
                'a': random.randint(0, 9999)
            }))

        result = self._dor.add_data_object(content_path, owner.identity, False, False, 'JSON', 'json')
        obj_id = result.obj_id

        wrong_user = self._known_user0

        meta = self._dor.get_meta(obj_id)
        assert(owner.identity.id == meta.owner_iid)
        assert(len(meta.tags) == 0)

        # try to set tags by non-owner
        try:
            self._dor.update_tags(obj_id, wrong_user, {'name': 'abc'})

        except UnsuccessfulRequestError as e:
            assert (e.details['reason'] == 'user is not the data object owner')

        # try to set tags by owner
        try:
            meta = self._dor.update_tags(obj_id, owner, {'name': 'abc'})
            assert(len(meta.tags) == 1)
            assert('name' in meta.tags)
            assert(meta.tags['name'] == 'abc')

        except UnsuccessfulRequestError:
            assert False

        # try to set tags by owner
        try:
            meta = self._dor.update_tags(obj_id, owner, {'name': 'bcd'})
            assert(len(meta.tags) == 1)
            assert('name' in meta.tags)
            assert(meta.tags['name'] == 'bcd')

        except UnsuccessfulRequestError:
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

        except UnsuccessfulRequestError:
            assert False

        # try to remove existing tag by owner
        try:
            meta = self._dor.remove_tags(obj_id, owner, ['name'])
            assert (len(meta.tags) == 0)

        except UnsuccessfulRequestError:
            assert False

        # try to set a complex tag by owner
        try:
            meta = self._dor.update_tags(obj_id, owner, {'profile': {
                'name': 'mr a',
                'email': 'somewhere@internet.com'
            }})
            assert(len(meta.tags) == 1)
            assert('profile' in meta.tags)
            assert('name' in meta.tags['profile'])
            assert('email' in meta.tags['profile'])

        except UnsuccessfulRequestError:
            assert False

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
        meta = self._dor.add_data_object(content_enc_path, owner1.identity, False, True, 'map', 'json')
        obj_id = meta.obj_id

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
                                         owner.identity, True, False, 'map', 'json')
        obj_id = meta.obj_id

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
        assert receiver_identity.id in meta.access

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
                                          owner.identity, False, False, 'map', 'json')
        meta1 = self._dor.add_data_object(self.generate_random_file(generate_random_string(4), 1024*1024),
                                          owner.identity, False, False, 'map', 'json')
        meta2 = self._dor.add_data_object(self.generate_random_file(generate_random_string(4), 1024*1024),
                                          owner.identity, False, False, 'map', 'json')
        obj_id0 = meta0.obj_id
        obj_id1 = meta1.obj_id
        obj_id2 = meta2.obj_id
        c_hash0 = meta0.c_hash
        c_hash1 = meta1.c_hash
        c_hash2 = meta2.c_hash

        # search for data objects
        result = self._dor.search(c_hashes=[c_hash0, c_hash1])
        logger.info(f"result={result}")
        assert len(result) == 2
        result = {i.obj_id: i.tags for i in result}
        assert obj_id0 in result
        assert obj_id1 in result

        # search for data objects
        result = self._dor.search(c_hashes=[c_hash2])
        logger.info(f"result={result}")
        assert len(result) == 1
        result = {i.obj_id: i.tags for i in result}
        assert obj_id2 in result

        self._dor.delete_data_object(obj_id0, owner)
        self._dor.delete_data_object(obj_id1, owner)
        self._dor.delete_data_object(obj_id2, owner)


if __name__ == '__main__':
    unittest.main()
