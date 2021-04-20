import unittest
import logging
import os
import time

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.rsakeypair import RSAKeyPair
from tests.testing_environment import TestingEnvironment

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

env = TestingEnvironment.get_instance('../config/testing-config.json')
logger = logging.getLogger(__name__)

#
# def create_authentication(url, body, auth_key, attachment_path=None):
#     return {
#         'public_key': auth_key.public_as_string(),
#         'signature': auth_key.sign_authentication_token(url, body, [attachment_path] if attachment_path else [])
#     }
#
#
# def create_authorisation(url, body, auth_key):
#     return {
#         'public_key': auth_key.public_as_string(),
#         'signature': auth_key.sign_authorisation_token(url, body)
#     }


class ECKeyPairTestCases(unittest.TestCase):
    def setUp(self):
        env.prepare_working_directory()
        self.key = ECKeyPair.create_new()

    def tearDown(self):
        pass

    def test_serialisation(self):
        password = 'test'

        pubkey_path = os.path.join(env.wd_path, 'pubkey.pem')
        prvkey_path = os.path.join(env.wd_path, 'prvkey.pem')
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

        assert(result0.private_key is not None)
        assert(result1.private_key is not None)
        assert(result2.private_key is not None)
        assert(result3.private_key is not None)
        assert(result4.private_key is not None)

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

    def test_authentication(self):
        url = "/repository/345345345lk3j45345ef3f34r3984r"
        body = {
            'a': 'asdasdas',
            'f': 2343
        }

        file_path = env.generate_random_file('data.dat', 1e6)

        # case 1: no body, no files
        signature = self.key.sign_authentication_token(url)
        assert self.key.verify_authentication_token(signature, url)

        # case 2: body, no files
        signature = self.key.sign_authentication_token(url, body)
        assert self.key.verify_authentication_token(signature, url, body)

        # case 3: no body, files
        signature = self.key.sign_authentication_token(url, files=[file_path])
        assert self.key.verify_authentication_token(signature, url, files={'label': file_path})

        # case 4: body, files
        signature = self.key.sign_authentication_token(url, body, [file_path])
        assert self.key.verify_authentication_token(signature, url, body, {'label': file_path})

    def test_authorisation(self):
        url = "/repository/345345345lk3j45345ef3f34r3984r"
        body = {
            'a': 'asdasdas',
            'f': 2343
        }

        # case 1a: no body, successful
        signature = self.key.sign_authorisation_token(url)
        assert self.key.verify_authorisation_token(signature, url)

        # case 1b: no body, unsuccessful
        time.sleep(11)
        assert not self.key.verify_authorisation_token(signature, url)

        # case 2a: body, successful
        signature = self.key.sign_authorisation_token(url, body)
        assert self.key.verify_authorisation_token(signature, url, body)

        # case 2b: body, unsuccessful
        time.sleep(11)
        assert not self.key.verify_authorisation_token(signature, url, body)


class RSAKeyPairTestCases(unittest.TestCase):
    def setUp(self):
        env.prepare_working_directory()
        self.key = RSAKeyPair.create_new()

    def tearDown(self):
        pass

    def test_serialisation(self):
        password = 'test'

        pubkey_path = os.path.join(env.wd_path, 'pubkey.pem')
        prvkey_path = os.path.join(env.wd_path, 'prvkey.pem')
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

        assert(result0.private_key is not None)
        assert(result1.private_key is not None)
        assert(result2.private_key is not None)
        assert(result3.private_key is not None)
        assert(result4.private_key is not None)

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


if __name__ == '__main__':
    unittest.main()
