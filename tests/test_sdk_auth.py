import os
import shutil
import unittest

from saas.core.helpers import generate_random_string
from saas.sdk.app.base import UserDB, UserAuth
from saas.sdk.app.exceptions import AppRuntimeError
from saas.sdk.helper import create_wd


class SDKAuthTestCase(unittest.TestCase):
    def setUp(self):
        self.wd_path = create_wd()
        self.secret = generate_random_string(32)

    def tearDown(self):
        shutil.rmtree(self.wd_path)

    def test_init_auth(self):
        secret = 'abcdefghijklmnopqrstuvwxyz012345'

        UserAuth.initialise(secret)
        h = UserAuth.get_password_hash('password')
        print(h)
        assert(h.startswith('$2b$12$'))

    def test_init_list_create_remove_user(self):
        UserDB.initialise(self.wd_path)

        # get all users. should be none.
        users = UserDB.all_users()
        print(users)
        assert(users is not None)
        assert(len(users) == 0)

        # create a new user
        user = UserDB.add_user('johndoe', 'John Doe', 'password')
        print(user)
        assert(user is not None)
        assert(os.path.isfile(user.keystore.path))

        # get all users. should be none.
        users = UserDB.all_users()
        print(users)
        assert(users is not None)
        assert(len(users) == 1)

        # try to create a user with the same username
        try:
            UserDB.add_user('johndoe', 'John Doe', 'password')
            assert False

        except AppRuntimeError as e:
            assert(e.reason == 'User account already exists')

        # delete user
        user = UserDB.delete_user('johndoe')
        assert(user is not None)
        assert(not os.path.isfile(user.keystore.path))
        users = UserDB.all_users()
        assert(len(users) == 0)

        # try to delete the user again
        try:
            UserDB.delete_user('johndoe')
            assert False

        except AppRuntimeError as e:
            assert(e.reason == 'User account does not exist')

    def test_enable_disable_user(self):
        UserDB.initialise(self.wd_path)

        # create a new user
        user = UserDB.add_user('johndoe', 'John Doe', 'password')
        print(user)
        assert(user is not None)
        assert(os.path.isfile(user.keystore.path))

        assert(user.disabled is False)
        user = UserDB.disable_user(user.login)
        assert(user.disabled is True)
        user = UserDB.enable_user(user.login)
        assert(user.disabled is False)


    def test_update_user(self):
        UserDB.initialise(self.wd_path)

        user = UserDB.add_user('update', 'Update User', 'password')
        print(user)
        assert (user is not None)
        assert (os.path.isfile(user.keystore.path))

        user = UserDB.update_user(user.login, False, user_display_name='New Username')
        assert (user.name == 'New Username')
        print(user)


    def test_update_user_password(self):
        UserDB.initialise(self.wd_path)

        user = UserDB.add_user('update', 'Update User', 'password')
        print(user)
        assert (user is not None)
        assert (os.path.isfile(user.keystore.path))
        user = UserDB.update_user(user.login, False, password=('password', 'newpassword'))
        print(user)


if __name__ == '__main__':
    unittest.main()
