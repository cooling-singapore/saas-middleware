import unittest
import logging

from flask import Blueprint, jsonify
from flask_cors import CORS

from saas.rest.proxy import EndpointProxy
from saas.utilities.blueprint_helpers import request_manager
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

    @request_manager.authentication_required
    def get_info(self):
        return jsonify({
            "message": "hello"
        }), 200


class TestProxy(EndpointProxy):
    def __init__(self, remote_address, sender):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address, sender)

    def get_info(self):
        r = self.get("/info")
        return r['reply']['message']


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
        proxy = TestProxy(node.rest.address(), node)

        bp = TestBlueprint()
        node.rest.add(bp.blueprint())

        result = proxy.get_info()
        assert(result == 'hello')


if __name__ == '__main__':
    unittest.main()
