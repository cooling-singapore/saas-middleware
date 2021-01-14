import unittest
import logging
import time

from tests.testing_environment import TestingEnvironment

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

env = TestingEnvironment.get_instance('../config/testing-config.json')
logger = logging.getLogger(__name__)

#
# def create_authentication(url, body, auth_key, attachment_path=None):
#     return {
#         'public_key': auth_key.public_as_string(),
#         'signature': auth_key.sign_authentication_token(url, body, [attachment_path] if attachment_path else [])
#     }
#
#
# def create_authorisation(url, body, auth_key):
#     return {
#         'public_key': auth_key.public_as_string(),
#         'signature': auth_key.sign_authorisation_token(url, body)
#     }


class ECKeyPairTestCases(unittest.TestCase):
    def setUp(self):
        env.prepare_working_directory()
        self.keys = env.generate_keys(1)

    def tearDown(self):
        pass

    def test_authentication(self):
        url = "/repository/345345345lk3j45345ef3f34r3984r"
        body = {
            'a': 'asdasdas',
            'f': 2343
        }

        file_path = env.generate_random_file('data.dat', 1e6)

        # case 1: no body, no files
        signature = self.keys[0].sign_authentication_token(url)
        assert self.keys[0].verify_authentication_token(signature, url)

        # case 2: body, no files
        signature = self.keys[0].sign_authentication_token(url, body)
        assert self.keys[0].verify_authentication_token(signature, url, body)

        # case 3: no body, files
        signature = self.keys[0].sign_authentication_token(url, files=[file_path])
        assert self.keys[0].verify_authentication_token(signature, url, files={'label': file_path})

        # case 4: body, files
        signature = self.keys[0].sign_authentication_token(url, body, [file_path])
        assert self.keys[0].verify_authentication_token(signature, url, body, {'label': file_path})

    def test_authorisation(self):
        url = "/repository/345345345lk3j45345ef3f34r3984r"
        body = {
            'a': 'asdasdas',
            'f': 2343
        }

        # case 1a: no body, successful
        signature = self.keys[0].sign_authorisation_token(url)
        assert self.keys[0].verify_authorisation_token(signature, url)

        # case 1b: no body, unsuccessful
        time.sleep(11)
        assert not self.keys[0].verify_authorisation_token(signature, url)

        # case 2a: body, successful
        signature = self.keys[0].sign_authorisation_token(url, body)
        assert self.keys[0].verify_authorisation_token(signature, url, body)

        # case 2b: body, unsuccessful
        time.sleep(11)
        assert not self.keys[0].verify_authorisation_token(signature, url, body)


if __name__ == '__main__':
    unittest.main()
