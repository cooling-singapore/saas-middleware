import unittest
import os
import logging
import time
import json
import requests

from saas.eckeypair import ECKeyPair

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)
datastore_path = '/Users/heikoaydt/Desktop/saas_env/testing'
test_file_path = os.path.join(datastore_path, 'data.zip')
test_file_path2 = os.path.join(datastore_path, 'data2.zip')
test_file_id = 'd53473e1328c325aae023bec037f2613b478375bf00f470a5b7f738a297cce98'

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


def add_data_object(sender, file_path, owner):
    url = "http://127.0.0.1:5000/repository"
    body = {
        'type': 'import',
        'header': {
            'type': 'map',
            'format': 'json',
            'created_t': 21342342,
            'created_by': 'heiko',
            'provenance': {
                'parents': ['p1', 'p2'],
                'process': 'proc03423',
                'parameters': {}
            }
        },
        'owner_public_key': owner.public_as_string()
    }
    authentication = create_authentication('POST:/', body, sender, file_path)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    with open(test_file_path, 'rb') as f:
        r = requests.post(url, data=content, files={'attachment': f.read()}).json()
        return r['reply']['data_object_id'] if 'data_object_id' in r['reply'] else None


def delete_data_object(sender, obj_id, owner):
    url = "http://127.0.0.1:5000/repository/{}".format(obj_id)
    body = {}
    authentication = create_authentication("DELETE:/{}".format(obj_id), body, sender)
    authorisation = create_authorisation("DELETE:/{}".format(obj_id), body, owner)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.delete(url, data=content).json()
    return r['reply']['header'] if 'header' in r['reply'] else None


def get_access_permissions(sender, obj_id):
    url = "http://127.0.0.1:5000/repository/{}/access".format(obj_id)
    body = {}
    authentication = create_authentication("GET:/{}/access".format(obj_id), body, sender)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']['access'] if 'access' in r['reply'] else None


def grant_access(sender, obj_id, user, owner):
    url = "http://127.0.0.1:5000/repository/{}/access".format(obj_id)
    body = {
        'user_public_key': user.public_as_string()
    }
    authentication = create_authentication("POST:/{}/access".format(obj_id), body, sender)
    authorisation = create_authorisation("POST:/{}/access".format(obj_id), body, owner)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.post(url, data=content).json()
    return r['reply']


def revoke_access(sender, obj_id, user, owner):
    url = "http://127.0.0.1:5000/repository/{}/access".format(obj_id)
    body = {
        'user_public_key': user.public_as_string()
    }
    authentication = create_authentication("DELETE:/{}/access".format(obj_id), body, sender)
    authorisation = create_authorisation("DELETE:/{}/access".format(obj_id), body, owner)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.delete(url, data=content).json()
    return r['reply']


def get_ownership(sender, obj_id):
    url = "http://127.0.0.1:5000/repository/{}/owner".format(obj_id)
    body = {}
    authentication = create_authentication("GET:/{}/owner".format(obj_id), body, sender)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']


def transfer_ownership(sender, obj_id, current_owner, new_owner):
    url = "http://127.0.0.1:5000/repository/{}/owner".format(obj_id)
    body = {
        'new_owner_public_key': new_owner.public_as_string()
    }
    authentication = create_authentication("PUT:/{}/owner".format(obj_id), body, sender)
    authorisation = create_authorisation("PUT:/{}/owner".format(obj_id), body, current_owner)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.put(url, data=content).json()
    return r['reply']


def get_header(sender, obj_id):
    url = "http://127.0.0.1:5000/repository/{}/header".format(obj_id)
    body = {}
    authentication = create_authentication("GET:/{}/header".format(obj_id), body, sender)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']


def export_data_object_content(sender, obj_id, owner, destination):
    url = "http://127.0.0.1:5000/repository/{}/content".format(obj_id)
    body = {
        'type': 'export'
    }
    authentication = create_authentication("GET:/{}/content".format(obj_id), body, sender)
    authorisation = create_authorisation("GET:/{}/content".format(obj_id), body, owner)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    with requests.get(url, data=content, stream=True) as r:
        if r.status_code == 401:
            return 401

        with open(destination, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

        return r.status_code


def fetch_data_object_content(sender, obj_id, owner):
    url = "http://127.0.0.1:5000/repository/{}/content".format(obj_id)
    body = {
        'type': 'internal'
    }
    authentication = create_authentication("GET:/{}/content".format(obj_id), body, sender)
    authorisation = create_authorisation("GET:/{}/content".format(obj_id), body, owner)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.get(url, data=content).json()
    return r['reply']['path'] if 'path' in r['reply'] else None


class DORRecordsTestCases(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    # def test_authentication(self):
    #     url = "/repository/345345345lk3j45345ef3f34r3984r"
    #     params = {
    #         'a': 'asdasdas',
    #         'f': 2343
    #     }
    #     file_path = os.path.join(datastore_path, 'data.zip')
    #     signature = key1.sign_authentication_token(url, params, [file_path])
    #     assert key1.verify_authentication_token(signature, url, params, {'label': file_path})
    #
    # def test_authorisation(self):
    #     url = "/repository/345345345lk3j45345ef3f34r3984r"
    #     params = {
    #         'a': 'asdasdas',
    #         'f': 2343
    #     }
    #     signature = key1.sign_authorisation_token(url, params)
    #     assert key1.verify_authorisation_token(signature, url, params)
    #
    #     time.sleep(7)
    #     assert not key1.verify_authorisation_token(signature, url, params)

    def test_add_delete_data_object(self):
        obj_id = add_data_object(key1, test_file_path, key2)
        logger.info("obj_id={}".format(obj_id))
        assert obj_id is not None
        assert obj_id == test_file_id

        header = delete_data_object(key1, obj_id, key2)
        logger.info("header={}".format(header))
        assert header is not None

    def test_grant_revoke_access(self):
        obj_id = add_data_object(key1, test_file_path, key2)
        logger.info("obj_id={}".format(obj_id))
        assert obj_id is not None
        assert obj_id == test_file_id

        permissions = get_access_permissions(key1, obj_id)
        logger.info("permissions={}".format(permissions))
        assert len(permissions) == 1
        assert permissions[0]['user_iid'] == key2.iid

        reply = grant_access(key1, obj_id, key3, key1)
        assert reply == 'Authorisation failed. Action not allowed.'

        permissions = get_access_permissions(key1, obj_id)
        logger.info("permissions={}".format(permissions))
        assert len(permissions) == 1
        assert permissions[0]['user_iid'] == key2.iid

        reply = grant_access(key1, obj_id, key3, key2)
        assert reply == 'Access granted.'

        permissions = get_access_permissions(key1, obj_id)
        logger.info("permissions={}".format(permissions))
        assert len(permissions) == 2
        assert permissions[0]['user_iid'] == key2.iid
        assert permissions[1]['user_iid'] == key3.iid

        reply = revoke_access(key1, obj_id, key3, key2)
        assert reply == 'Access revoked.'

        permissions = get_access_permissions(key1, obj_id)
        logger.info("permissions={}".format(permissions))
        assert len(permissions) == 1
        assert permissions[0]['user_iid'] == key2.iid

        header = delete_data_object(key1, obj_id, key2)
        logger.info("header={}".format(header))
        assert header is not None


    def test_transfer_ownership(self):
        obj_id = add_data_object(key1, test_file_path, key2)
        logger.info("obj_id={}".format(obj_id))
        assert obj_id is not None
        assert obj_id == test_file_id

        owner_info = get_ownership(key1, obj_id)
        logger.info("owner_info={}".format(owner_info))
        assert owner_info['owner_iid'] == key2.iid

        reply = transfer_ownership(key1, obj_id, key1, key3)
        assert reply == 'Authorisation failed. Action not allowed.'

        reply = transfer_ownership(key1, obj_id, key2, key3)
        assert reply != 'Authorisation failed. Action not allowed.'

        owner_info = get_ownership(key1, obj_id)
        logger.info("owner_info={}".format(owner_info))
        assert owner_info['owner_iid'] == key3.iid

        header = delete_data_object(key1, obj_id, key2)
        logger.info("header={}".format(header))
        assert header is None

        header = delete_data_object(key1, obj_id, key3)
        logger.info("header={}".format(header))
        assert header is not None


    def test_get_data_object(self):
        obj_id = add_data_object(key1, test_file_path, key2)
        logger.info("obj_id={}".format(obj_id))
        assert obj_id is not None
        assert obj_id == test_file_id

        header = get_header(key1, obj_id)
        logger.info("header={}".format(header))
        assert header is not None

        reply = export_data_object_content(key1, obj_id, key1, test_file_path2)
        assert reply == 401

        reply = export_data_object_content(key1, obj_id, key2, test_file_path2)
        assert reply == 200

        path = fetch_data_object_content(key1, obj_id, key1)
        logger.info("path={}".format(path))
        assert path is not None

        header = delete_data_object(key1, obj_id, key2)
        logger.info("header={}".format(header))
        assert header is not None


if __name__ == '__main__':
    unittest.main()
