import shutil
import tempfile
import unittest
import logging
import os

from saas.keystore.schemas import GithubCredentials, SSHCredentials
from saas.keystore.keystore import Keystore
from saas.log import Logging

Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


class KeystoreTestCase(unittest.TestCase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)

    def setUp(self):
        self.wd_path = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.wd_path)

    def test_create_and_load(self):
        keystore = Keystore.create(self.wd_path, 'name', 'email', 'password')
        assert(keystore is not None)
        assert(keystore.identity.name == 'name')
        assert(keystore.identity.email == 'email')
        assert(keystore.identity.nonce == 1)

        keystore_id = keystore.identity.id
        keystore_path = os.path.join(self.wd_path, f"{keystore_id}.json")
        assert(os.path.isfile(keystore_path))

        keystore = Keystore.load(keystore_path, 'password')
        assert(keystore is not None)
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
        assert(identity.verify_integrity())

        keystore = Keystore.load(os.path.join(self.wd_path, f"{keystore_id}.json"), 'password')
        assert(keystore is not None)
        assert(keystore.identity.id == keystore_id)
        assert(keystore.identity.name == name)
        assert(keystore.identity.email == email)
        assert(keystore.identity.nonce == 2)

    def test_add_get_object_key(self):
        keystore = Keystore.create(self.wd_path, 'name', 'email', 'password')
        assert(keystore.identity.name == 'name')
        assert(keystore.identity.email == 'email')

        obj_id = 'obj1'
        obj_key = 'key1'

        keystore.content_keys.update(obj_id, obj_key)
        assert(keystore.content_keys.get(obj_id) == obj_key)

        keystore.sync()

        keystore = Keystore.load(os.path.join(self.wd_path, f"{keystore.identity.id}.json"), 'password')
        assert(keystore.identity.name == 'name')
        assert(keystore.identity.email == 'email')

        assert(keystore.content_keys.get(obj_id) == obj_key)

    def test_add_credentials(self):
        url = 'https://github.com/cooling-singapore/saas-middleware'
        login = 'johndoe'
        personal_access_token = 'token'
        host = '192.168.0.1'
        key = '<<<key here>>>'

        keystore = Keystore.create(self.wd_path, 'name', 'email', 'password')
        assert(keystore.identity.name == 'name')
        assert(keystore.identity.email == 'email')

        keystore.github_credentials.update(url, GithubCredentials(login=login,
                                                                  personal_access_token=personal_access_token))

        keystore.ssh_credentials.update('my-remote-machine', SSHCredentials(host=host, login=login, key=key,
                                                                            key_is_password=True))
        keystore.sync()

        keystore = Keystore.load(os.path.join(self.wd_path, f"{keystore.identity.id}.json"), 'password')
        c = keystore.github_credentials.get(url)
        print(c)
        assert(c is not None)
        assert(c.login == login)
        assert(c.personal_access_token == personal_access_token)

        c = keystore.ssh_credentials.get('my-remote-machine')
        print(c)
        assert(c is not None)
        assert(c.host == host)
        assert(c.login == login)
        assert(c.key == key)


if __name__ == '__main__':
    unittest.main()
