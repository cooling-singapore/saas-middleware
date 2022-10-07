import shutil
import tempfile
import unittest
import logging
import os

from saas.core.schemas import GithubCredentials, SSHCredentials
from saas.core.keystore import Keystore
from saas.core.eckeypair import ECKeyPair
from saas.core.rsakeypair import RSAKeyPair
from saas.core.logging import Logging

Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


class ECKeyPairTestCases(unittest.TestCase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)

    def setUp(self):
        self.key = ECKeyPair.create_new()
        self.wd_path = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.wd_path)

    def test_serialisation(self):
        password = 'test'

        pubkey_path = os.path.join(self.wd_path, 'pubkey.pem')
        prvkey_path = os.path.join(self.wd_path, 'prvkey.pem')
        self.key.write_public(pubkey_path)
        self.key.write_private(prvkey_path, password)

        pubkey = self.key.public_key
        pubkey_bytes = self.key.public_as_bytes()
        pubkey_string0 = self.key.public_as_string(truncate=False)
        pubkey_string1 = self.key.public_as_string(truncate=True)
        result0 = ECKeyPair.from_public_key(pubkey)
        result1 = ECKeyPair.from_public_key_bytes(pubkey_bytes)
        result2 = ECKeyPair.from_public_key_string(pubkey_string0)
        result3 = ECKeyPair.from_public_key_string(pubkey_string1)
        result4 = ECKeyPair.from_public_key_file(pubkey_path)

        assert(result0.private_key is None)
        assert(result1.private_key is None)
        assert(result2.private_key is None)
        assert(result3.private_key is None)
        assert(result4.private_key is None)

        assert(result0.iid == self.key.iid)
        assert(result1.iid == self.key.iid)
        assert(result2.iid == self.key.iid)
        assert(result3.iid == self.key.iid)
        assert(result4.iid == self.key.iid)

        private_key = self.key.private_key
        prvkey_string0 = self.key.private_as_string(password, truncate=False)
        prvkey_string1 = self.key.private_as_string(password, truncate=True)
        prvkey_string2 = self.key.private_as_string(truncate=False)
        prvkey_string3 = self.key.private_as_string(truncate=True)

        result0 = ECKeyPair.from_private_key_file(prvkey_path, password)
        result1 = ECKeyPair.from_private_key(private_key)
        result2 = ECKeyPair.from_private_key_string(prvkey_string0, password)
        result3 = ECKeyPair.from_private_key_string(prvkey_string1, password)
        result4 = ECKeyPair.from_private_key_string(prvkey_string2)
        result5 = ECKeyPair.from_private_key_string(prvkey_string3)

        assert(result0.iid == self.key.iid)
        assert(result1.iid == self.key.iid)
        assert(result2.iid == self.key.iid)
        assert(result3.iid == self.key.iid)
        assert(result4.iid == self.key.iid)
        assert(result5.iid == self.key.iid)

    def test_signing(self):
        message0 = 'test0'.encode('utf-8')
        message1 = 'test1'.encode('utf-8')

        signature0 = self.key.sign(message0)
        assert(self.key.verify(message0, signature0))
        assert(not self.key.verify(message1, signature0))


class RSAKeyPairTestCases(unittest.TestCase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)

    def setUp(self):
        self.key = RSAKeyPair.create_new()
        self.wd_path = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.wd_path)

    def test_serialisation(self):
        password = 'test'

        pubkey_path = os.path.join(self.wd_path, 'pubkey.pem')
        prvkey_path = os.path.join(self.wd_path, 'prvkey.pem')
        self.key.write_public(pubkey_path)
        self.key.write_private(prvkey_path, password)

        pubkey = self.key.public_key
        pubkey_bytes = self.key.public_as_bytes()
        pubkey_string0 = self.key.public_as_string(truncate=False)
        pubkey_string1 = self.key.public_as_string(truncate=True)
        result0 = RSAKeyPair.from_public_key(pubkey)
        result1 = RSAKeyPair.from_public_key_bytes(pubkey_bytes)
        result2 = RSAKeyPair.from_public_key_string(pubkey_string0)
        result3 = RSAKeyPair.from_public_key_string(pubkey_string1)
        result4 = RSAKeyPair.from_public_key_file(pubkey_path)

        assert(result0.private_key is None)
        assert(result1.private_key is None)
        assert(result2.private_key is None)
        assert(result3.private_key is None)
        assert(result4.private_key is None)

        assert(result0.iid == self.key.iid)
        assert(result1.iid == self.key.iid)
        assert(result2.iid == self.key.iid)
        assert(result3.iid == self.key.iid)
        assert(result4.iid == self.key.iid)

        private_key = self.key.private_key
        prvkey_string0 = self.key.private_as_string(password, truncate=False)
        prvkey_string1 = self.key.private_as_string(password, truncate=True)
        prvkey_string2 = self.key.private_as_string(truncate=False)
        prvkey_string3 = self.key.private_as_string(truncate=True)

        result0 = RSAKeyPair.from_private_key_file(prvkey_path, password)
        result1 = RSAKeyPair.from_private_key(private_key)
        result2 = RSAKeyPair.from_private_key_string(prvkey_string0, password)
        result3 = RSAKeyPair.from_private_key_string(prvkey_string1, password)
        result4 = RSAKeyPair.from_private_key_string(prvkey_string2)
        result5 = RSAKeyPair.from_private_key_string(prvkey_string3)

        assert(result0.iid == self.key.iid)
        assert(result1.iid == self.key.iid)
        assert(result2.iid == self.key.iid)
        assert(result3.iid == self.key.iid)
        assert(result4.iid == self.key.iid)
        assert(result5.iid == self.key.iid)

    def test_signing(self):
        message0 = 'test0'.encode('utf-8')
        message1 = 'test1'.encode('utf-8')

        signature0 = self.key.sign(message0)
        assert(self.key.verify(message0, signature0))
        assert(not self.key.verify(message1, signature0))

    def test_encryption(self):
        plaintext = "test"

        encrypted = self.key.encrypt(plaintext.encode('utf-8'))
        decrypted = self.key.decrypt(encrypted).decode('utf-8')

        assert(plaintext == decrypted)


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


class LoggingTestCase(unittest.TestCase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)

    def setUp(self):
        self.wd_path = tempfile.mkdtemp()

    def tearDown(self):
        Logging.remove_all_handlers()
        shutil.rmtree(self.wd_path)

    def test_defaults(self):
        Logging.initialise()
        logger = Logging.get('test')

        logger.info("you can see me!")
        logger.debug("you should not be able to see me!")

    def test_log_to_separate_file(self):
        default_log_path = os.path.join(self.wd_path, 'log.default')
        custom_log_path = os.path.join(self.wd_path, 'log.custom')

        Logging.initialise(log_path=default_log_path)

        default = Logging.get('default_logger')
        custom = Logging.get('custom_logger', custom_log_path=custom_log_path)

        default.info("this should go into the default log file")
        custom.info("this should go into the default log file AND the custom log file")

        with open(default_log_path, 'r') as f:
            default_lines = f.readlines()
            print(default_lines)
        assert(len(default_lines) == 2)

        with open(custom_log_path, 'r') as f:
            custom_lines = f.readlines()
            print(custom_lines)
        assert(len(custom_lines) == 1)

    def test_rollover(self):
        log_path0 = os.path.join(self.wd_path, 'log')
        log_path1 = os.path.join(self.wd_path, 'log.1')
        log_path2 = os.path.join(self.wd_path, 'log.2')

        Logging.initialise(log_path=log_path0, max_bytes=80)

        logger = Logging.get('logger')
        assert(os.path.isfile(log_path0))
        assert(not os.path.isfile(log_path1))
        assert(not os.path.isfile(log_path2))

        logger.info('msg')
        assert(os.path.isfile(log_path0))
        assert(not os.path.isfile(log_path1))
        assert(not os.path.isfile(log_path2))

        logger.info('msg')
        assert(os.path.isfile(log_path0))
        assert(os.path.isfile(log_path1))
        assert(not os.path.isfile(log_path2))

        logger.info('msg')
        assert(os.path.isfile(log_path0))
        assert(os.path.isfile(log_path1))
        assert(os.path.isfile(log_path2))


if __name__ == '__main__':
    unittest.main()
