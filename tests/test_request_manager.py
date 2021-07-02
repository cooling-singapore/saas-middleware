import json
import logging
import unittest

from flask import jsonify, Flask

from saas.cryptography.eckeypair import ECKeyPair
from saas.utilities.blueprint_helpers import request_manager, create_authentication
from tests.base_testcase import TestCaseBase

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


def init_test_app():
    app = Flask(__name__)
    app.config['TESTING'] = True

    test_class = TestCaseBase()
    test_class.initialise()
    node = test_class.get_node('node', enable_rest=False)

    request_manager.init_app(app, node)

    return test_class, app, node


class AuthenticationTestCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_class, app, node = init_test_app()

        cls.test_class = test_class
        cls.client = app.test_client()
        cls.key = ECKeyPair.create_new()
        cls.node = node

        @app.route('/test')
        @request_manager.authentication_required
        def test_route():
            return jsonify('test')

    @classmethod
    def tearDownClass(cls):
        cls.test_class.cleanup()

    def test_no_authentication(self):
        response = self.client.get('/test')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json.get('reply'), 'Missing authentication information. Authentication failed.')

    def test_invalid_authentication(self):
        authentication = create_authentication('wrong_url', self.key)
        content = {
            'authentication': json.dumps(authentication),
        }
        response = self.client.get('/test', data=content)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json.get('reply'), 'Mismatching signature. Authentication failed.')

    def test_valid_authentication(self):
        authentication = create_authentication('GET:/test', self.key)
        content = {
            'authentication': json.dumps(authentication),
        }
        response = self.client.get('/test', data=content)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json.get('reply'), 'test')


class BodyVerificationTestCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_class, app, node = init_test_app()

        cls.test_class = test_class
        cls.client = app.test_client()
        cls.key = ECKeyPair.create_new()
        cls.node = node

        test_body_specification = {
            "type": "object",
            "properties": {
                "test": {"type": "string"},
            },
        }

        @app.route('/test')
        @request_manager.authentication_required
        @request_manager.verify_request_body(test_body_specification)
        def test_route():
            return jsonify('test')

    @classmethod
    def tearDownClass(cls):
        cls.test_class.cleanup()

    def get_response(self, body):
        authentication = create_authentication('GET:/test', self.key, body)
        content = {
            'body': json.dumps(body),
            'authentication': json.dumps(authentication)
        }
        response = self.client.get('/test', data=content)
        return response

    def test_valid_body(self):
        valid_body = {
            'test': 'valid'
        }

        response = self.get_response(valid_body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json.get('reply'), 'test')

    def test_invalid_body(self):
        invalid_body = {
            'test': 0
        }

        response = self.get_response(invalid_body)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json.get('reply').split(':')[0], 'Malformed content')


if __name__ == '__main__':
    unittest.main()
