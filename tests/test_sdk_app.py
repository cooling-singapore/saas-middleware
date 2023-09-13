import shutil
import time
import unittest
from threading import Thread
from typing import List

from fastapi import Depends
from pydantic import BaseModel
from saas.rest.proxy import EndpointProxy

from saas.core.keystore import Keystore
from saas.rest.schemas import EndpointDefinition
from saas.sdk.app.base import Application, User, UserDB, UserAuth, get_current_active_user, UserProfile
from saas.sdk.helper import create_wd, create_rnd_hex_string


class TestResponse(BaseModel):
    message: str


class TestApp(Application):
    def __init__(self, address: (str, int), node_address: (str, int), wd_path: str, endpoint_prefix: (str, str)):
        super().__init__(address, node_address, endpoint_prefix,
                         wd_path, 'Test App', 'v0.0.1', 'This is a test app')

    def endpoints(self) -> List[EndpointDefinition]:
        return [
            EndpointDefinition('GET', self.endpoint_prefix, 'unprotected', self.unprotected, TestResponse, None),
            EndpointDefinition('GET', self.endpoint_prefix, 'protected', self.protected, TestResponse, None)
        ]

    def protected(self, current_user: User = Depends(get_current_active_user)) -> TestResponse:
        return TestResponse(message=f"hello protected world!!! {current_user.login}")

    def unprotected(self) -> TestResponse:
        return TestResponse(message='hello open world!!!')


class TestAppBaseProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int), endpoint_prefix: (str, str), username: str, password: str):
        super().__init__(endpoint_prefix, remote_address, credentials=(username, password))

    def profile(self) -> UserProfile:
        result = self.get('user/profile')
        return UserProfile.parse_obj(result)

    def update_name(self, name: str) -> UserProfile:
        result = self.put('user/profile', body={
            'name': name
        })
        return UserProfile.parse_obj(result)

    def update_password(self, password: (str, str)) -> UserProfile:
        result = self.put('user/profile', body={
            'password': password
        })
        return UserProfile.parse_obj(result)


class TestAppProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int), endpoint_prefix: (str, str), username: str, password: str):
        super().__init__(endpoint_prefix, remote_address, credentials=(username, password))

    def unprotected(self) -> TestResponse:
        result = self.get('unprotected')
        return TestResponse.parse_obj(result)

    def protected(self) -> TestResponse:
        result = self.get('protected')
        return TestResponse.parse_obj(result)


class Server(Thread):
    def __init__(self, address: (str, int), node_address: (str, int), endpoint_prefix: (str, str),
                 wd_path: str) -> None:
        super().__init__()
        self._address = address
        self._node_address = node_address
        self._wd_path = wd_path
        self._endpoint_prefix = endpoint_prefix
        self._running = True

    def shutdown(self) -> None:
        self._running = False

    def run(self) -> None:
        # initialise user DB and Auth
        UserDB.initialise(self._wd_path)
        UserAuth.initialise(create_rnd_hex_string(32))

        # create user
        UserDB.add_user('foo.bar@somewhere.com', 'Foo Bar', 'password')

        # start up the app
        app = TestApp(self._address, self._node_address, self._wd_path, self._endpoint_prefix)
        app.startup()

        while self._running:
            time.sleep(0.2)


class SDKAppTestCase(unittest.TestCase):
    _address = ('127.0.0.1', 5101)
    _endpoint_prefix = ('/v1', 'test')
    _wd_path: str = None
    _server: Server = None
    _proxy: TestAppProxy = None
    _keystore = None
    _known_user = None

    @classmethod
    def setUpClass(cls):
        cls._wd_path = create_wd()
        cls._keystore = Keystore.create(cls._wd_path, 'Foo Bar', 'foo.bar@somewhere.com', 'password')
        cls._known_user = Keystore.create(cls._wd_path, 'John Doe', 'john.doe@somewhere.com', 'password')

        # create and start server
        cls._server = Server(cls._address, None, cls._endpoint_prefix, cls._wd_path)
        cls._server.start()
        cls._proxy = TestAppProxy(cls._address, cls._endpoint_prefix, 'foo.bar@somewhere.com', 'password')
        cls._base_proxy = TestAppBaseProxy(cls._address, (cls._endpoint_prefix[0], None),
                                           'foo.bar@somewhere.com', 'password')
        time.sleep(20)

    @classmethod
    def tearDownClass(cls):
        # shutdown server
        cls._server.shutdown()
        time.sleep(1)

        # delete working directory
        shutil.rmtree(cls._wd_path)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_get_token(self):
        token = self._proxy.session.token
        assert(token is not None)

    def test_unprotected_endpoint(self):
        response = self._proxy.unprotected()
        print(response)
        assert(response.message == 'hello open world!!!')

    def test_protected_endpoint(self):
        response = self._proxy.protected()
        print(response)
        assert('foo.bar@somewhere.com' in response.message)

    def test_get_user_profile(self):
        profile = self._base_proxy.profile()
        print(profile)
        assert(profile is not None)
        assert(profile.login == 'foo.bar@somewhere.com')
        assert(profile.name == 'Foo Bar')

    def test_update_user_name(self):
        profile = self._base_proxy.update_name('new_name')
        print(profile)
        assert(profile is not None)
        assert(profile.login == 'foo.bar@somewhere.com')
        assert(profile.name == 'new_name')

        profile = self._base_proxy.profile()
        print(profile)
        assert(profile is not None)
        assert(profile.name == 'new_name')

    def test_update_user_password(self):
        # should fail
        try:
            self._base_proxy.update_password(('wrong_password', 'lalala'))
            assert False
        except Exception as e:
            print(e)
            assert True

        # should work
        try:
            profile = self._base_proxy.update_password(('password', 'lalala'))
            print(profile)
            assert(profile is not None)
        except Exception as e:
            print(e)
            assert False

        # should fail now
        proxy0 = TestAppBaseProxy(self._address, (self._endpoint_prefix[0], None), 'foo.bar@somewhere.com', 'password')
        try:
            proxy0.profile()
            assert False
        except Exception as e:
            print(e)
            assert True

        # should work
        proxy1 = TestAppBaseProxy(self._address, (self._endpoint_prefix[0], None), 'foo.bar@somewhere.com', 'lalala')
        try:
            proxy1.profile()
            print(profile)
            assert True
        except Exception as e:
            print(e)
            assert False

        # change it back to the original password
        self._base_proxy.update_password(('lalala', 'password'))


if __name__ == '__main__':
    unittest.main()
