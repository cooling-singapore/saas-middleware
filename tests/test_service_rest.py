import os
import random
import shutil
import string
import time
import unittest
import logging

from pydantic import BaseModel
from saascore.api.sdk.exceptions import UnsuccessfulRequestError
from saascore.api.sdk.proxies import EndpointProxy
from saascore.exceptions import SaaSException
from saascore.helpers import get_timestamp_now
from saascore.keystore.keystore import Keystore
from saascore.log import Logging

from saas.rest.auth import VerifyAuthorisation
from saas.rest.schemas import EndpointDefinition
from tests.base_testcase import TestCaseBase

Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)

endpoint_prefix = "/api/v1/test"


class TestResponse(BaseModel):
    key: str
    value: str


class TestDeleteRequest(BaseModel):
    key: str


class TestException(SaaSException):
    pass


class TestRESTService:
    def __init__(self):
        self._objects = {}

    def endpoints(self) -> list:
        return [
            EndpointDefinition('POST', endpoint_prefix, 'create/{value}',
                               self.rest_post, TestResponse, None),

            EndpointDefinition('GET', endpoint_prefix, 'read/{key}',
                               self.rest_get, TestResponse, None),

            EndpointDefinition('PUT', endpoint_prefix, 'update/{key}/{value}',
                               self.rest_put, TestResponse, None),

            EndpointDefinition('DELETE', endpoint_prefix, 'delete/{key}',
                               self.rest_delete, TestResponse, None),

            EndpointDefinition('DELETE', endpoint_prefix, 'delete_body',
                               self.rest_delete_with_body, TestResponse, None),

            EndpointDefinition('DELETE', endpoint_prefix, 'delete_auth',
                               self.rest_delete_with_body, TestResponse, [VerifyAuthorisation])
        ]

    def rest_post(self, value: str) -> TestResponse:
        key = None
        while key is None or key in self._objects:
            key = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))

        self._objects[key] = value
        return TestResponse(key=key, value=self._objects[key])

    def rest_get(self, key: str) -> TestResponse:
        if key in self._objects:
            return TestResponse(key=key, value=self._objects[key])

        raise TestException("obj does not exist", details={
            'key': key
        })

    def rest_put(self, key: str, value: str) -> TestResponse:
        if key in self._objects:
            self._objects[key] = value
            return TestResponse(key=key, value=self._objects[key])

        raise TestException("obj does not exist", details={
            'key': key
        })

    def rest_delete(self, key: str) -> TestResponse:
        if key in self._objects:
            value = self._objects.pop(key)
            return TestResponse(key=key, value=value)

        raise TestException("obj does not exist", details={
            'key': key
        })

    def rest_delete_with_body(self, r: TestDeleteRequest) -> TestResponse:
        if r.key in self._objects:
            value = self._objects.pop(r.key)
            return TestResponse(key=r.key, value=value)

        raise TestException("obj does not exist", details={
            'key': r.key
        })


class TestProxy(EndpointProxy):
    def __init__(self, remote_address):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address)

    def create(self, value: str) -> TestResponse:
        result = self.post(f"/create/{value}")
        return TestResponse.parse_obj(result)

    def read(self, key: str) -> TestResponse:
        result = self.get(f"/read/{key}")
        return TestResponse.parse_obj(result)

    def update(self, key: str, value: str) -> TestResponse:
        result = self.put(f"/update/{key}/{value}")
        return TestResponse.parse_obj(result)

    def remove(self, key: str) -> TestResponse:
        result = self.delete(f"/delete/{key}")
        return TestResponse.parse_obj(result)

    def remove_with_body(self, key: str) -> TestResponse:
        result = self.delete(f"/delete_body", body={'key': key})
        return TestResponse.parse_obj(result)

    def remove_with_auth(self, key: str, authority: Keystore = None) -> TestResponse:
        result = self.delete(f"/delete_auth", body={'key': key}, with_authorisation_by=authority)
        return TestResponse.parse_obj(result)


class RESTServiceTestCase(unittest.TestCase, TestCaseBase):
    _wd_path = os.path.join(os.environ['HOME'], 'testing', str(get_timestamp_now()))
    _node = None
    _proxy = None

    def __init__(self, method_name='runTest'):
        unittest.TestCase.__init__(self, method_name)
        TestCaseBase.__init__(self)

    @classmethod
    def tearDownClass(cls):
        if cls._node is not None:
            shutil.rmtree(cls._wd_path, ignore_errors=True)
            cls._node.shutdown(leave_network=False)

    def setUp(self):
        self.initialise()

        if RESTServiceTestCase._node is None:
            RESTServiceTestCase._node = self.get_node('node', enable_rest=True, keep_track=False,
                                                      wd_path=RESTServiceTestCase._wd_path)

            rest_service = TestRESTService()
            RESTServiceTestCase._node.rest.add(rest_service.endpoints())

            RESTServiceTestCase._proxy = TestProxy(RESTServiceTestCase._node.rest.address())
            time.sleep(1)

    def tearDown(self):
        self.cleanup()

    def test_create_read(self):
        result = self._proxy.create('hello world')
        assert(result is not None)
        assert(result.value == 'hello world')

        result = self._proxy.read(result.key)
        assert(result is not None)
        assert(result.value == 'hello world')

    def test_update_ok(self):
        result = self._proxy.create('hello world')
        assert(result is not None)
        assert(result.value == 'hello world')
        key = result.key

        result = self._proxy.update(key, 'hello new world')
        assert(result is not None)
        assert(result.value == 'hello new world')

    def test_update_fails(self):
        result = self._proxy.create('hello world')
        assert(result is not None)
        assert(result.value == 'hello world')

        try:
            self._proxy.update('invalid', 'hello new world')
            assert False

        except UnsuccessfulRequestError:
            assert True

    def test_delete_ok(self):
        result = self._proxy.create('hello world')
        assert(result is not None)
        assert(result.value == 'hello world')
        key = result.key

        result = self._proxy.remove(key)
        assert(result is not None)

        try:
            self._proxy.read(key)
            assert False

        except UnsuccessfulRequestError:
            assert True

    def test_delete_fails(self):
        result = self._proxy.create('hello world')
        assert(result is not None)
        assert(result.value == 'hello world')
        key = result.key

        try:
            self._proxy.remove('invalid_key')
            assert False

        except UnsuccessfulRequestError:
            assert True

        try:
            self._proxy.read(key)
            assert True

        except UnsuccessfulRequestError:
            assert False

    def test_delete_with_body(self):
        result = self._proxy.create('hello world')
        key = result.key

        result = self._proxy.remove_with_body(key)
        assert(result is not None)

        try:
            self._proxy.read(key)
            assert False

        except UnsuccessfulRequestError:
            assert True

    def test_delete_with_auth(self):
        result = self._proxy.create('hello world')
        key = result.key

        good_authority = self._node.keystore
        bad_authority = self.create_keystores(1)[0]

        try:
            # this should fail because the 'bad' authority is not known to the node
            self._proxy.remove_with_auth(key, authority=bad_authority)
            assert False

        except UnsuccessfulRequestError as e:
            assert e.details['reason'] == 'unknown identity'

        try:
            # this should succeed because the 'good' authority is known to the node
            result = self._proxy.remove_with_auth(key, authority=good_authority)
            assert (result is not None)

        except UnsuccessfulRequestError:
            assert False

        try:
            self._proxy.read(key)
            assert False

        except UnsuccessfulRequestError:
            assert True


if __name__ == '__main__':
    unittest.main()
