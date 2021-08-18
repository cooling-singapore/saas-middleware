import unittest
import logging
import os

from saas.keystore.assets.credentials import GithubCredentialsAsset, SSHCredentialsAsset
from saas.keystore.keystore import Keystore
from tests.base_testcase import TestCaseBase

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class KeystoreTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

    def tearDown(self):
        self.cleanup()

    def test_create_and_load(self):
        keystore = Keystore.create(self.wd_path, 'name', 'email', 'password')
        assert(keystore is not None)
        assert(keystore.has_asset('master-key'))
        assert(keystore.has_asset('signing-key'))
        assert(keystore.has_asset('encryption-key'))
        assert(keystore.identity.name == 'name')
        assert(keystore.identity.email == 'email')
        assert(keystore.identity.nonce == 1)

        keystore_id = keystore.identity.id
        keystore_path = os.path.join(self.wd_path, f"{keystore_id}.json")
        assert(os.path.isfile(keystore_path))

        keystore = Keystore.load(self.wd_path, keystore_id, 'password')
        assert(keystore is not None)
        assert(keystore.has_asset('master-key'))
        assert(keystore.has_asset('signing-key'))
        assert(keystore.has_asset('encryption-key'))
        assert(keystore.identity.id == keystore_id)
        assert(keystore.identity.name == 'name')
        assert(keystore.identity.email == 'email')
        assert(keystore.identity.nonce == 1)

    def test_update(self):
        keystore = Keystore.create(self.wd_path, 'name', 'email', 'password')
        keystore_id = keystore.identity.id
        assert(keystore.identity.name == 'name')
        assert(keystore.identity.email == 'email')

        name = 'name2'
        email = 'email2'

        # perform update
        identity = keystore.update_profile(name=name, email=email)
        logger.info(f"signature={identity.signature}")
        assert(identity.signature is not None)
        assert(keystore.identity.name == name)
        assert(keystore.identity.email == email)

        # verify authenticity
        assert(identity.is_authentic())

        keystore = Keystore.load(self.wd_path, keystore_id, 'password')
        assert(keystore is not None)
        assert(keystore.has_asset('master-key'))
        assert(keystore.has_asset('signing-key'))
        assert(keystore.has_asset('encryption-key'))
        assert(keystore.identity.id == keystore_id)
        assert(keystore.identity.name == name)
        assert(keystore.identity.email == email)
        assert(keystore.identity.nonce == 2)

    def test_add_get_object_key(self):
        keystore = Keystore.create(self.wd_path, 'name', 'email', 'password')
        assert(keystore.identity.name == 'name')
        assert(keystore.identity.email == 'email')

        asset = keystore.get_asset('content-keys')
        assert(asset is not None)

        obj_id = 'obj1'
        obj_key = 'key1'

        asset.update(obj_id, obj_key)
        assert(asset.get(obj_id) == obj_key)

        keystore.update_asset(asset)

        keystore = Keystore.load(self.wd_path, keystore.identity.id, 'password')
        assert(keystore.identity.name == 'name')
        assert(keystore.identity.email == 'email')

        asset = keystore.get_asset('content-keys')
        assert(asset.get(obj_id) == obj_key)

    def test_add_credentials(self):
        url = 'https://github.com/cooling-singapore/saas-middleware'
        login = 'johndoe'
        personal_access_token = 'token'
        host = '192.168.0.1'
        password = 'password'

        keystore = Keystore.create(self.wd_path, 'name', 'email', 'password')
        assert(keystore.identity.name == 'name')
        assert(keystore.identity.email == 'email')

        github = GithubCredentialsAsset.create('github-cred')
        github.update(url, login, personal_access_token)

        ssh = SSHCredentialsAsset.create('ssh-cred')
        ssh.update('my-remote-machine', host, login, password)

        keystore.update_asset(github)
        keystore.update_asset(ssh)

        keystore = Keystore.load(self.wd_path, keystore.identity.id, 'password')
        assert(keystore.has_asset('github-cred'))
        assert(keystore.has_asset('ssh-cred'))

        github = keystore.get_asset('github-cred')
        c = github.get(url)
        print(c)
        assert(c is not None)
        assert(c['login'] == login)
        assert(c['personal_access_token'] == personal_access_token)

        ssh = keystore.get_asset('ssh-cred')
        c = ssh.get('my-remote-machine')
        print(c)
        assert(c is not None)
        assert(c['host'] == host)
        assert(c['login'] == login)
        assert(c['password'] == password)


if __name__ == '__main__':
    unittest.main()
