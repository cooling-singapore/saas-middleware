import unittest
import logging
import time
import os
import time
import json
import requests


from tests.testing_environment import TestingEnvironment
from saas.eckeypair import hash_file_content
from saas.utilities.general_helpers import object_to_ordered_list
from saas.node import Node
from saas.dor.protocol import DataObjectRepositoryP2PProtocol

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

env = TestingEnvironment.get_instance('/Users/heikoaydt/Desktop/saas_env/testing-config.json')
logger = logging.getLogger(__name__)


# def create_authentication(url, body, auth_key, attachment_path=None):
#     return {
#         'public_key': auth_key.public_as_string(),
#         'signature':
#             auth_key.sign_authentication_token(url, body, [attachment_path]) if attachment_path else
#             auth_key.sign_authentication_token(url, body)
#     }


def create_authentication2(url, auth_key, body=None, attachment_path=None):
    return {
        'public_key': auth_key.public_as_string(),
        'signature':
            auth_key.sign_authentication_token(url, body=body, files=[attachment_path]) if attachment_path else
            auth_key.sign_authentication_token(url, body=body)
    }


# def create_authorisation(url, body, auth_key):
#     return {
#         'public_key': auth_key.public_as_string(),
#         'signature': auth_key.sign_authorisation_token(url, body)
#     }


def create_authorisation2(url, auth_key, body=None):
    return {
        'public_key': auth_key.public_as_string(),
        'signature': auth_key.sign_authorisation_token(url, body)
    }


def add_data_object(sender, owner):
    url = "http://127.0.0.1:5000/repository"
    body = {
        'type': 'data_object',
        'owner_public_key': owner.public_as_string(),
        'descriptor': {
            'data_type': 'map',
            'data_format': 'json',
            'created_t': 21342342,
            'created_by': 'heiko',
            'recipe': {
                'output_name': 'asdasd',
                'job_descriptor': {
                    'processor_id': '34532452345',
                    'input': [

                    ],
                    'output': [

                    ]
                }
            }
        }
    }
    test_file_path = env.generate_zero_file('test000.dat', 1024*1024)
    test_obj_id = '0b4c2fdfb49f6ee3190b28ad5b615884e591e003398c8fd2468852b6a754353c'

    authentication = create_authentication2('POST:/repository', sender, body, test_file_path)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    with open(test_file_path, 'rb') as f:
        r = requests.post(url, data=content, files={'attachment': f.read()}).json()
        return test_obj_id, r['reply']['data_object_id'] if 'data_object_id' in r['reply'] else None


def delete_data_object(sender, obj_id, owner):
    url = "http://127.0.0.1:5000/repository/{}".format(obj_id)
    # body = {}
    authentication = create_authentication2("DELETE:/repository/{}".format(obj_id), sender)
    authorisation = create_authorisation2("DELETE:/repository/{}".format(obj_id), owner)
    content = {
        # 'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.delete(url, data=content).json()
    return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None


def get_descriptor(sender, obj_id):
    url = "http://127.0.0.1:5000/repository/{}/descriptor".format(obj_id)
    authentication = create_authentication2("GET:/repository/{}/descriptor".format(obj_id), sender)
    content = {
        # 'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None


def get_access_permissions(sender, obj_id):
    url = "http://127.0.0.1:5000/repository/{}/access".format(obj_id)
    # body = {}
    authentication = create_authentication2("GET:/repository/{}/access".format(obj_id), sender)
    content = {
        # 'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']['access'] if 'access' in r['reply'] else None


def grant_access(sender, obj_id, user, owner):
    url = "http://127.0.0.1:5000/repository/{}/access".format(obj_id)
    body = {
        'user_public_key': user.public_as_string()
    }
    authentication = create_authentication2("POST:/repository/{}/access".format(obj_id), sender, body)
    authorisation = create_authorisation2("POST:/repository/{}/access".format(obj_id), owner, body)
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
    authentication = create_authentication2("DELETE:/repository/{}/access".format(obj_id), sender, body)
    authorisation = create_authorisation2("DELETE:/repository/{}/access".format(obj_id), owner, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.delete(url, data=content).json()
    return r['reply']


def get_ownership(sender, obj_id):
    url = "http://127.0.0.1:5000/repository/{}/owner".format(obj_id)
    # body = {}
    authentication = create_authentication2("GET:/repository/{}/owner".format(obj_id), sender)
    content = {
        # 'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']


def transfer_ownership(sender, obj_id, current_owner, new_owner):
    url = "http://127.0.0.1:5000/repository/{}/owner".format(obj_id)
    body = {
        'new_owner_public_key': new_owner.public_as_string()
    }
    authentication = create_authentication2("PUT:/repository/{}/owner".format(obj_id), sender, body)
    authorisation = create_authorisation2("PUT:/repository/{}/owner".format(obj_id), current_owner, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.put(url, data=content).json()
    return r['reply']


def export_data_object_content(sender, obj_id, owner, destination):
    url = "http://127.0.0.1:5000/repository/{}/content".format(obj_id)
    authentication = create_authentication2("GET:/repository/{}/content".format(obj_id), sender)
    authorisation = create_authorisation2("GET:/repository/{}/content".format(obj_id), owner)
    content = {
        # 'body': json.dumps(body),
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


# def fetch_data_object_content(sender, obj_id, owner):
#     url = "http://127.0.0.1:5000/repository/{}/content".format(obj_id)
#     body = {
#         'type': 'internal'
#     }
#     authentication = create_authentication2("GET:/{}/content".format(obj_id), sender, body)
#     authorisation = create_authorisation2("GET:/{}/content".format(obj_id), owner, body)
#     content = {
#         'body': json.dumps(body),
#         'authentication': json.dumps(authentication),
#         'authorisation': json.dumps(authorisation)
#     }
#
#     r = requests.get(url, data=content).json()
#     return r['reply']['path'] if 'path' in r['reply'] else None


class DORBlueprintTestCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env.start_flask_app()

    @classmethod
    def tearDownClass(cls):
        env.stop_flask_app()

    def setUp(self):
        env.prepare_working_directory()
        self.keys = env.generate_keys(3)

    def tearDown(self):
        pass

    def test_add_delete_data_object(self):
        # create the data object
        ref_obj_id, obj_id = add_data_object(self.keys[0], self.keys[1])
        logger.info("obj_id: reference={} actual={}".format(ref_obj_id, obj_id))
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        # get the descriptor of the data object
        descriptor1 = get_descriptor(self.keys[0], obj_id)
        logger.info("descriptor1={}".format(descriptor1))
        assert descriptor1 is not None

        # delete the data object
        descriptor2 = delete_data_object(self.keys[0], obj_id, self.keys[1])
        logger.info("descriptor2={}".format(descriptor2))
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_grant_revoke_access(self):
        ref_obj_id, obj_id = add_data_object(self.keys[0], self.keys[1])
        logger.info("obj_id: reference={} actual={}".format(ref_obj_id, obj_id))
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        permissions = get_access_permissions(self.keys[0], obj_id)
        logger.info("permissions={}".format(permissions))
        assert len(permissions) == 1
        assert self.keys[1].iid in permissions

        reply = grant_access(self.keys[0], obj_id, self.keys[2], self.keys[0])
        assert reply == 'Authorisation failed.'

        permissions = get_access_permissions(self.keys[0], obj_id)
        logger.info("permissions={}".format(permissions))
        assert len(permissions) == 1
        assert permissions[0] == self.keys[1].iid

        reply = grant_access(self.keys[0], obj_id, self.keys[2], self.keys[1])
        assert reply == 'Access granted.'

        permissions = get_access_permissions(self.keys[0], obj_id)
        logger.info("permissions={}".format(permissions))
        assert len(permissions) == 2
        assert self.keys[1].iid in permissions
        assert self.keys[2].iid in permissions

        reply = revoke_access(self.keys[0], obj_id, self.keys[2], self.keys[1])
        assert reply == 'Access revoked.'

        permissions = get_access_permissions(self.keys[0], obj_id)
        logger.info("permissions={}".format(permissions))
        assert len(permissions) == 1
        assert self.keys[1].iid in permissions

        descriptor = delete_data_object(self.keys[0], obj_id, self.keys[1])
        logger.info("descriptor={}".format(descriptor))
        assert descriptor is not None

    def test_transfer_ownership(self):
        ref_obj_id, obj_id = add_data_object(self.keys[0], self.keys[1])
        logger.info("obj_id: reference={} actual={}".format(ref_obj_id, obj_id))
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        owner_info = get_ownership(self.keys[0], obj_id)
        logger.info("owner_info={}".format(owner_info))
        assert owner_info['owner_iid'] == self.keys[1].iid

        reply = transfer_ownership(self.keys[0], obj_id, self.keys[0], self.keys[2])
        assert reply == 'Authorisation failed.'

        reply = transfer_ownership(self.keys[0], obj_id, self.keys[1], self.keys[2])
        logger.info("reply={}".format(reply))
        assert reply == "Ownership of data object '{}' transferred to '{}'.".format(obj_id, self.keys[2].iid)

        owner_info = get_ownership(self.keys[0], obj_id)
        logger.info("owner_info={}".format(owner_info))
        assert owner_info['owner_iid'] == self.keys[2].iid

        descriptor = delete_data_object(self.keys[0], obj_id, self.keys[1])
        logger.info("descriptor={}".format(descriptor))
        assert descriptor is None

        descriptor = delete_data_object(self.keys[0], obj_id, self.keys[2])
        logger.info("descriptor={}".format(descriptor))
        assert descriptor is not None

    def test_get_data_object(self):
        ref_obj_id, obj_id = add_data_object(self.keys[0], self.keys[1])
        logger.info("obj_id: reference={} actual={}".format(ref_obj_id, obj_id))
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        descriptor1 = get_descriptor(self.keys[0], obj_id)
        logger.info("descriptor1={}".format(descriptor1))
        assert descriptor1 is not None

        destination = os.path.join(env.wd_path, 'test_copy.dat')
        reply = export_data_object_content(self.keys[0], obj_id, self.keys[0], destination)
        assert reply == 401
        assert not os.path.exists(destination)

        reply = export_data_object_content(self.keys[0], obj_id, self.keys[1], destination)
        assert reply == 200
        assert os.path.isfile(destination)

        # path = fetch_data_object_content(self.keys[0], obj_id, self.keys[0])
        # logger.info("path={}".format(path))
        # assert path is not None

        descriptor2 = delete_data_object(self.keys[0], obj_id, self.keys[1])
        logger.info("descriptor2={}".format(descriptor2))
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_fetch_data_object(self):
        ref_obj_id, obj_id = add_data_object(self.keys[0], self.keys[1])
        logger.info("obj_id: reference={} actual={}".format(ref_obj_id, obj_id))
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        descriptor1 = get_descriptor(self.keys[0], obj_id)
        logger.info("descriptor1={}".format(descriptor1))
        assert descriptor1 is not None

        # create the receiving node
        node = Node('receiver', env.wd_path)
        node.initialise_identity(env.wd_path)
        node.start_server((env.p2p_host, env.p2p_port))

        peer_address = (env.app_service_p2p_host, env.app_service_p2p_port)
        destination = os.path.join(env.wd_path, 'test_copy.dat')

        protocol = DataObjectRepositoryP2PProtocol(node)
        protocol.send_fetch(peer_address, obj_id, destination)
        assert os.path.isfile(destination)

        node.stop_server()

        descriptor2 = delete_data_object(self.keys[0], obj_id, self.keys[1])
        logger.info("descriptor2={}".format(descriptor2))
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)


if __name__ == '__main__':
    unittest.main()
