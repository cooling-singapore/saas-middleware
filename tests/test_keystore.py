import unittest
import logging
import os

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

        self.name = 'name'
        self.email = 'email'
        self.password = 'password'

    def setUp(self):
        self.initialise()

    def tearDown(self):
        self.cleanup()

    def test_create_and_load(self):
        keystore = Keystore.create(self.wd_path, self.name, self.email, self.password)
        assert(keystore is not None)
        assert(keystore.identity is not None)
        assert(keystore.name() == self.name)
        assert(keystore.email() == self.email)

        keystore_id = keystore.id()
        master_path = os.path.join(self.wd_path, f"{keystore_id}.master")
        keystore_path = os.path.join(self.wd_path, f"{keystore_id}.keystore")
        assert(os.path.isfile(master_path))
        assert(os.path.isfile(keystore_path))

        assert(Keystore.is_valid(self.wd_path, keystore_id))

        keystore = Keystore.load(self.wd_path, keystore_id, self.password)
        assert(keystore is not None)
        assert(keystore.identity is not None)
        assert(keystore.id() == keystore_id)
        assert(keystore.name() == self.name)
        assert(keystore.email() == self.email)

    def test_update(self):
        keystore = Keystore.create(self.wd_path, self.name, self.email, self.password)
        keystore_id = keystore.id()
        assert(keystore.name() == self.name)
        assert(keystore.email() == self.email)

        name = 'name2'
        email = 'email2'

        keystore.update(name, email)
        assert(keystore.name() == name)
        assert(keystore.email() == email)

        keystore = Keystore.load(self.wd_path, keystore_id, self.password)
        assert(keystore is not None)
        assert(keystore.identity is not None)
        assert(keystore.id() == keystore_id)
        assert(keystore.name() == name)
        assert(keystore.email() == email)

    def test_add_get_object_key(self):
        keystore = Keystore.create(self.wd_path, self.name, self.email, self.password)
        keystore_id = keystore.id()

        obj_id = 'obj1'
        obj_key = b'key1'
        keystore.add_object_key(obj_id, obj_key)
        assert(keystore.get_object_key(obj_id) == obj_key)

        keystore = Keystore.load(self.wd_path, keystore_id, self.password)
        assert(keystore.get_object_key(obj_id) == obj_key)


if __name__ == '__main__':
    unittest.main()
