import time
import unittest
import logging

from flask import Blueprint, jsonify
from flask_cors import CORS

from saas.cryptography.eckeypair import ECKeyPair
from saas.rest.proxy import EndpointProxy
from saas.rest.request_manager import request_manager, verify_authorisation_token, sign_authorisation_token
from tests.base_testcase import TestCaseBase

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


endpoint_prefix = "/api/v1/test"


class TestBlueprint:
    def blueprint(self):
        blueprint = Blueprint('test', __name__, url_prefix=endpoint_prefix)
        blueprint.add_url_rule('/info', self.get_info.__name__, self.get_info, methods=['GET'])
        CORS(blueprint)
        return blueprint

    @request_manager.verify_request_body({'type':'string'})
    def get_info(self):
        return jsonify({
            "message": "hello"
        }), 200


class TestProxy(EndpointProxy):
    def __init__(self, remote_address):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address)

    def get_info(self):
        code, r = self.get("/info", body="test")
        return r['message'] if code == 200 else None


class RESTServiceTestCase(unittest.TestCase, TestCaseBase):
    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    def setUp(self):
        self.initialise()

    def tearDown(self):
        self.cleanup()

    def test_simple_get(self):
        node = self.get_node(f"node_0", enable_rest=True)
        proxy = TestProxy(node.rest.address())

        bp = TestBlueprint()
        node.rest.add(bp.blueprint())

        result = proxy.get_info()
        assert(result == 'hello')

    def test_authorisation(self):
        url = "/repository/345345345lk3j45345ef3f34r3984r"
        body = {
            'a': 'asdasdas',
            'f': 2343
        }

        keystore = self.create_keystores(1)[0]

        # case 1a: no body, successful
        signature = sign_authorisation_token(keystore, url)
        assert verify_authorisation_token(keystore.identity, signature, url)

        # case 1b: no body, unsuccessful
        time.sleep(11)
        assert not verify_authorisation_token(keystore.identity, signature, url)

        # case 2a: body, successful
        signature = sign_authorisation_token(keystore, url, body)
        assert verify_authorisation_token(keystore.identity, signature, url, body)

        # case 2b: body, unsuccessful
        time.sleep(11)
        assert not verify_authorisation_token(keystore.identity, signature, url, body)


if __name__ == '__main__':
    unittest.main()
