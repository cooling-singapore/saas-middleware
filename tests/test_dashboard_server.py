import os
import shutil
import unittest

from flask_jwt_extended import create_access_token

from apps.dashboard.server.app import create_app
from apps.dashboard.server.config import TestConfig


class TokenLoginTest(unittest.TestCase):
    def setUp(self):
        self.config = TestConfig
        app = create_app(self.config)
        app.config['TESTING'] = True

        self.app = app
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.config.DATASTORE)
        os.mkdir(self.config.DATASTORE)

    def get_login_response(self, username, password):
        response = self.client.post('/login', follow_redirects=True,
                                    data=dict(username=username, password=password))
        data = response.json

        return data

    def test_login_success(self):
        login_response = self.get_login_response('admin', 'password')

        self.assertIn('access_token', login_response)

    def test_login_fail(self):
        login_response = self.get_login_response('admin', 'wrong_password')

        self.assertNotIn('access_token', login_response)

    def test_restricted_path_success(self):
        with self.app.app_context():
            access_token = create_access_token(identity='admin')

        response = self.client.get('/login/admin', follow_redirects=True,
                                   headers={'Authorization': f'Bearer {access_token}'})

        self.assertEqual(response.status_code, 200)

    def test_restricted_path_failure(self):
        with self.app.app_context():
            access_token = create_access_token(identity='test')

        response = self.client.get('/login/admin', follow_redirects=True,
                                   headers={'Authorization': f'Bearer {access_token}'})

        self.assertEqual(response.status_code, 500)


if __name__ == '__main__':
    unittest.main()
