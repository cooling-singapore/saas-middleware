import os
import pytest

from saas.sdk.app.base import UserDB, UserAuth
from saas.sdk.app.exceptions import AppRuntimeError


def test_init_auth():
    secret = 'abcdefghijklmnopqrstuvwxyz012345'

    UserAuth.initialise(secret)
    h = UserAuth.get_password_hash('password')
    print(h)
    assert (h.startswith('$2b$12$'))


def test_init_list_create_remove_user(temp_directory):
    UserDB.initialise(temp_directory)

    # get all users. should be none.
    users = UserDB.all_users()
    print(users)
    assert (users is not None)
    assert (len(users) == 0)

    # create a new user
    user = UserDB.add_user('johndoe', 'John Doe', 'password')
    print(user)
    assert (user is not None)
    assert (os.path.isfile(user.keystore.path))

    # get all users. should be none.
    users = UserDB.all_users()
    print(users)
    assert (users is not None)
    assert (len(users) == 1)

    # try to create a user with the same username
    with pytest.raises(AppRuntimeError) as e:
        UserDB.add_user('johndoe', 'John Doe', 'password')
    assert (e.value.reason == 'User account already exists')

    # delete user
    user = UserDB.delete_user('johndoe')
    assert (user is not None)
    assert (not os.path.isfile(user.keystore.path))
    users = UserDB.all_users()
    assert (len(users) == 0)

    # try to delete the user again
    with pytest.raises(AppRuntimeError) as e:
        UserDB.delete_user('johndoe')
    assert (e.value.reason == 'User account does not exist')


def test_enable_disable_user(temp_directory):
    UserDB.initialise(temp_directory)

    # create a new user
    user = UserDB.add_user('johndoe', 'John Doe', 'password')
    print(user)
    assert (user is not None)
    assert (os.path.isfile(user.keystore.path))

    assert (user.disabled is False)
    user = UserDB.disable_user(user.login)
    assert (user.disabled is True)
    user = UserDB.enable_user(user.login)
    assert (user.disabled is False)


def test_update_user(temp_directory):
    UserDB.initialise(temp_directory)

    login = 'user@somehwere.com'
    user = UserDB.add_user(login, 'name', 'password')
    print(user)
    assert (user is not None)
    assert (os.path.isfile(user.keystore.path))

    user = UserDB.update_user(user.login, False, user_display_name='New Username')
    assert (user.name == 'New Username')
    print(user)

    user = UserDB.delete_user(login)
    print(user)
    assert (user is not None)


def test_update_user_password(temp_directory):
    UserDB.initialise(temp_directory)

    login = 'user@somehwere.com'
    user = UserDB.add_user(login, 'name', 'password')
    print(user)
    assert (user is not None)
    assert (os.path.isfile(user.keystore.path))

    user = UserDB.update_user(user.login, False, password=('password', 'newpassword'))
    print(user)

    user = UserDB.delete_user(login)
    print(user)
    assert (user is not None)
