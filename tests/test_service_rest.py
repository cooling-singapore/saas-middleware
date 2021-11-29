import time
import unittest
import logging

from pydantic import BaseModel

from saas.logging import Logging
from saas.rest.blueprint import SaaSBlueprint, create_ok_response
from saas.rest.proxy import EndpointProxy
from saas.rest.request_manager import request_manager, verify_authorisation_token, sign_authorisation_token
from tests.base_testcase import TestCaseBase

Logging.initialise(logging.DEBUG)
Logging.get(__name__)

endpoint_prefix = "/api/v1/test"


class TestBlueprint(SaaSBlueprint):
    class TestRequest(BaseModel):
        __root__: dict

    class TestResponse(BaseModel):
        message: str

    def __init__(self):
        super().__init__('test', __name__, endpoint_prefix)

        self.add_rule('info/<value>', self.get_info, ['GET'])

    @request_manager.verify_request_body(TestRequest)
    @request_manager.handle_request(TestResponse)
    def get_info(self, value: str):
        body = request_manager.get_request_variable('body')

        return create_ok_response({
            'message': f"{value} {body['value']}"
        })


class TestProxy(EndpointProxy):
    def __init__(self, remote_address):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address)

    def get_info(self, value: str):
        return self.get(f"/info/{value}", body={'value': 'world'})


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
        node.rest.add(bp.generate_blueprint())

        result = proxy.get_info('hello')
        assert(result['message'] == 'hello world')

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
