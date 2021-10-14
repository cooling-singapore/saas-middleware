import unittest
import logging
import os

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.rsakeypair import RSAKeyPair
from tests.base_testcase import TestCaseBase

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class ECKeyPairTestCases(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()
        self.key = ECKeyPair.create_new()

    def tearDown(self):
        self.cleanup()

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


class RSAKeyPairTestCases(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()
        self.key = RSAKeyPair.create_new()

    def tearDown(self):
        self.cleanup()

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


if __name__ == '__main__':
    unittest.main()
