import os
import logging
import unittest

from saas_cli import parse_args, load_keystore
from tests.testing_environment import TestingEnvironment

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

env = TestingEnvironment.get_instance('../config/testing-config.json')
logger = logging.getLogger(__name__)


class CLITestCase(unittest.TestCase):
    def setUp(self):
        env.prepare_working_directory()

        self.password = 'pwd!@#'

    def tearDown(self):
        pass

    def test_cmd_init(self):
        args = {
            'keystore': env.wd_path,
            'password': self.password,
            'keystore-id': None
        }
        keystore_id = load_keystore(args)
        assert(keystore_id is None)

        args = [
            '--keystore', env.wd_path,
            'init',
            '--name', 'name', '--email', 'email@internet.com', '--password', self.password
        ]
        keystore_id = parse_args(args)
        assert(keystore_id is not None)

        master_path = os.path.join(env.wd_path, f"{keystore_id}.master")
        keystore_path = os.path.join(env.wd_path, f"{keystore_id}.keystore")
        assert(os.path.isfile(master_path))
        assert(os.path.isfile(keystore_path))

        args = {
            'keystore': env.wd_path,
            'password': self.password,
            'keystore-id': None
        }
        keystore = load_keystore(args)
        assert(keystore_id == keystore.identity.iid)

        args = {
            'keystore': env.wd_path,
            'password': self.password,
            'keystore-id': keystore_id
        }
        keystore = load_keystore(args)
        assert(keystore_id == keystore.identity.iid)

        args = {
            'keystore': env.wd_path,
            'password': self.password,
            'keystore-id': 'sdfsldfkhsd'
        }
        keystore = load_keystore(args)
        assert(keystore is None)


if __name__ == '__main__':
    unittest.main()
