import unittest
import os
import logging
import time

from saas.eckeypair import ECKeyPair

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)
datastore_path = '/Users/heikoaydt/Desktop/saas_env/testing'


def create_keys(password):
    k1_path = os.path.join(datastore_path, "key1.pem")
    k2_path = os.path.join(datastore_path, "key2.pem")
    k3_path = os.path.join(datastore_path, "key3.pem")

    if os.path.isfile(k1_path):
        k1 = ECKeyPair.from_private_key_file(k1_path, password)
    else:
        k1 = ECKeyPair.create_new()
        k1.write_private(k1_path, password)

    if os.path.isfile(k2_path):
        k2 = ECKeyPair.from_private_key_file(k2_path, password)
    else:
        k2 = ECKeyPair.create_new()
        k2.write_private(k2_path, password)

    if os.path.isfile(k3_path):
        k3 = ECKeyPair.from_private_key_file(k3_path, password)
    else:
        k3= ECKeyPair.create_new()
        k3.write_private(k3_path, password)

    return k1, k2, k3


def create_authentication(url, body, auth_key, attachment_path=None):
    return {
        'public_key': auth_key.public_as_string(),
        'signature': auth_key.sign_authentication_token(url, body, [attachment_path] if attachment_path else [])
    }


def create_authorisation(url, body, auth_key):
    return {
        'public_key': auth_key.public_as_string(),
        'signature': auth_key.sign_authorisation_token(url, body)
    }


key1, key2, key3 = create_keys("test")
logger.info("key1={} iid1={}".format(key1.public_as_string(), key1.iid))
logger.info("key2={} iid1={}".format(key2.public_as_string(), key2.iid))
logger.info("key3={} iid1={}".format(key3.public_as_string(), key3.iid))


class ECKeyPairTestCases(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_authentication(self):
        url = "/repository/345345345lk3j45345ef3f34r3984r"
        params = {
            'a': 'asdasdas',
            'f': 2343
        }
        file_path = os.path.join(datastore_path, 'data.zip')
        signature = key1.sign_authentication_token(url, params, [file_path])
        assert key1.verify_authentication_token(signature, url, params, {'label': file_path})

    def test_authorisation(self):
        url = "/repository/345345345lk3j45345ef3f34r3984r"
        params = {
            'a': 'asdasdas',
            'f': 2343
        }
        signature = key1.sign_authorisation_token(url, params)
        assert key1.verify_authorisation_token(signature, url, params)

        time.sleep(11)
        assert not key1.verify_authorisation_token(signature, url, params)


if __name__ == '__main__':
    unittest.main()
