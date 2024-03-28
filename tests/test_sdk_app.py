import socket
import time
from threading import Thread
from typing import List

import pytest
from fastapi import Depends
from pydantic import BaseModel

from saas.rest.exceptions import UnsuccessfulRequestError, AuthorisationFailedError
from saas.rest.proxy import EndpointProxy

from saas.rest.schemas import EndpointDefinition
from saas.sdk.app.base import Application, User, UserDB, UserAuth, get_current_active_user, UserProfile
from saas.sdk.app.exceptions import AppRuntimeError
from tests.base_testcase import create_rnd_hex_string, PortMaster


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


server_address = PortMaster.generate_rest_address()
server_endpoint_prefix = ('/v1', 'test')
user_name = 'Foo Bar'
user_email = 'foo.bar@somewhere.com'
user_password = 'password'


@pytest.fixture(scope="module")
def sdk_test_server(temp_directory, keystore):
    server = Server(server_address, None, server_endpoint_prefix, temp_directory)
    server.start()
    time.sleep(20)
    yield server
    server.shutdown()


@pytest.fixture()
def server_proxy():
    return TestAppProxy(server_address, server_endpoint_prefix, user_email, user_password)


@pytest.fixture()
def base_proxy():
    return TestAppBaseProxy(server_address, (server_endpoint_prefix[0], None), user_email, user_password)


def test_server_port(temp_directory):
    # block the port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((server_address[0], server_address[1]))
    except Exception as e:
        print(e)

    # start up the app
    app = TestApp(server_address, None, temp_directory, server_endpoint_prefix)
    try:
        app.startup(n_attempts=1)
        assert False

    except AppRuntimeError:
        assert True

    finally:
        server_socket.close()


def test_get_token(sdk_test_server, server_proxy):
    token = server_proxy.session.token
    assert(token is not None)


def test_unprotected_endpoint(sdk_test_server, server_proxy):
    response = server_proxy.unprotected()
    print(response)
    assert(response.message == 'hello open world!!!')


def test_protected_endpoint(sdk_test_server, server_proxy):
    response = server_proxy.protected()
    print(response)
    assert('foo.bar@somewhere.com' in response.message)


def test_get_user_profile(sdk_test_server, base_proxy):
    profile = base_proxy.profile()
    print(profile)
    assert(profile is not None)
    assert(profile.login == 'foo.bar@somewhere.com')
    assert(profile.name == 'Foo Bar')


def test_update_user_name(sdk_test_server, base_proxy):
    profile = base_proxy.update_name('new_name')
    print(profile)
    assert(profile is not None)
    assert(profile.login == 'foo.bar@somewhere.com')
    assert(profile.name == 'new_name')

    profile = base_proxy.profile()
    print(profile)
    assert(profile is not None)
    assert(profile.name == 'new_name')


def test_update_user_password(sdk_test_server, base_proxy):
    # should fail
    with pytest.raises(UnsuccessfulRequestError) as e:
        base_proxy.update_password(('wrong_password', 'lalala'))
    print(e)

    # should work
    try:
        profile = base_proxy.update_password((user_password, 'lalala'))
    except Exception as e:
        print(e)
        assert False
    else:
        print(profile)
        assert(profile is not None)

    # should fail now
    proxy0 = TestAppBaseProxy(server_address, (server_endpoint_prefix[0], None), user_email, user_password)
    with pytest.raises(AuthorisationFailedError) as e:
        proxy0.profile()
    print(e)

    # should work
    proxy1 = TestAppBaseProxy(server_address, (server_endpoint_prefix[0], None), user_email, 'lalala')
    try:
        proxy1.profile()
    except Exception as e:
        print(e)
        assert False
    else:
        print(profile)

    # change it back to the original password
    base_proxy.update_password(('lalala', user_password))
