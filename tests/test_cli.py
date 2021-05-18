import os
import logging
import unittest

from saas.nodedb.blueprint import NodeDBProxy
from saas_cli import parse_args, load_keystore, cmd_initialise_service
from tests.base_testcase import TestCaseBase

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class CLITestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

        self.password = 'pwd!@#'

    def tearDown(self):
        self.cleanup()

    def test_cmd_init(self):
        args = {
            'keystore': self.wd_path,
            'password': self.password,
            'keystore-id': None
        }
        keystore_id = load_keystore(args)
        assert(keystore_id is None)

        args = [
            '--keystore', self.wd_path,
            'init',
            '--name', 'name', '--email', 'email@internet.com', '--password', self.password
        ]
        keystore_id = parse_args(args)
        assert(keystore_id is not None)

        master_path = os.path.join(self.wd_path, f"{keystore_id}.master")
        keystore_path = os.path.join(self.wd_path, f"{keystore_id}.keystore")
        assert(os.path.isfile(master_path))
        assert(os.path.isfile(keystore_path))

        args = {
            'keystore': self.wd_path,
            'password': self.password,
            'keystore-id': None
        }
        keystore = load_keystore(args)
        assert(keystore_id == keystore.identity.iid)

        args = {
            'keystore': self.wd_path,
            'password': self.password,
            'keystore-id': keystore_id
        }
        keystore = load_keystore(args)
        assert(keystore_id == keystore.identity.iid)

        args = {
            'keystore': self.wd_path,
            'password': self.password,
            'keystore-id': 'sdfsldfkhsd'
        }
        keystore = load_keystore(args)
        assert(keystore is None)

    def test_cmd_initialise_service(self):
        args = [
            '--keystore', self.wd_path,
            'init',
            '--name', 'name', '--email', 'email@internet.com', '--password', self.password
        ]
        keystore_id = parse_args(args)
        assert(keystore_id is not None)

        service_host = '127.0.0.1'
        service_rest_port = 5002
        service_p2p_port = 4001

        args = {
            'keystore': self.wd_path,
            'datastore': self.wd_path,
            'host': service_host,
            'rest-port': service_rest_port,
            'p2p-port': service_p2p_port,
            'boot-node': f"{service_host}:{service_p2p_port}",
            'service': 'full',
            'keystore-id': keystore_id,
            'password': self.password
        }
        node = cmd_initialise_service(args)
        proxy = NodeDBProxy(node.rest.address(), node.identity())
        result = proxy.get_node()
        logger.info(result)
        assert(result is not None)
        assert(result['rest_service_address'][0] == service_host)
        assert(result['rest_service_address'][1] == service_rest_port)

        node.shutdown()


if __name__ == '__main__':
    unittest.main()
