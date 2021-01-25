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
from saas.utilities.blueprint_helpers import create_authentication, create_authorisation
from saas.node import Node
from saas.dor.protocol import DataObjectRepositoryP2PProtocol

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

env = TestingEnvironment.get_instance('../config/testing-config.json')
logger = logging.getLogger(__name__)


def add_data_object(sender, owner):
    url = "http://127.0.0.1:5000/repository"
    body = {
        'type': 'data_object',
        'owner_public_key': owner.public_as_string(),
        'descriptor': {
            'data_type': 'map',
            'data_format': 'json',
            'created_t': 21342342,
            'created_by': 'heiko'
        }
    }
    test_file_path = env.generate_zero_file('test000.dat', 1024*1024)
    test_obj_id = '12edb4bcd29126086a30f3a1ee9220d02317684a6d41c181152fba752fe86ff0'

    authentication = create_authentication('POST:/repository', sender, body, test_file_path)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    with open(test_file_path, 'rb') as f:
        r = requests.post(url, data=content, files={'attachment': f.read()}).json()
        return test_obj_id, r['reply']['data_object_id'] if 'data_object_id' in r['reply'] else None


def add_random_data_object(sender, owner, filename):
    url = "http://127.0.0.1:5000/repository"
    body = {
        'type': 'data_object',
        'owner_public_key': owner.public_as_string(),
        'descriptor': {
            'data_type': 'map',
            'data_format': 'json',
            'created_t': 21342342,
            'created_by': 'heiko'
        }
    }
    test_file_path = env.generate_random_file(filename, 1024*1024)

    authentication = create_authentication('POST:/repository', sender, body, test_file_path)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    with open(test_file_path, 'rb') as f:
        r = requests.post(url, data=content, files={'attachment': f.read()}).json()
        return r['reply']['data_object_id'] if 'data_object_id' in r['reply'] else None


def delete_data_object(sender, obj_id, owner):
    url = f"http://127.0.0.1:5000/repository/{obj_id}"
    authentication = create_authentication(f"DELETE:/repository/{obj_id}", sender)
    authorisation = create_authorisation(f"DELETE:/repository/{obj_id}", owner)
    content = {
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.delete(url, data=content).json()
    return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None


def get_descriptor(sender, obj_id):
    url = f"http://127.0.0.1:5000/repository/{obj_id}/descriptor"
    authentication = create_authentication(f"GET:/repository/{obj_id}/descriptor", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None


def get_access_permissions(sender, obj_id):
    url = f"http://127.0.0.1:5000/repository/{obj_id}/access"
    authentication = create_authentication(f"GET:/repository/{obj_id}/access", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']['access'] if 'access' in r['reply'] else None


def grant_access(sender, obj_id, user, owner):
    url = f"http://127.0.0.1:5000/repository/{obj_id}/access"
    body = {
        'user_public_key': user.public_as_string()
    }
    authentication = create_authentication(f"POST:/repository/{obj_id}/access", sender, body)
    authorisation = create_authorisation(f"POST:/repository/{obj_id}/access", owner, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.post(url, data=content).json()
    return r['reply']


def revoke_access(sender, obj_id, user, owner):
    url = f"http://127.0.0.1:5000/repository/{obj_id}/access"
    body = {
        'user_public_key': user.public_as_string()
    }
    authentication = create_authentication(f"DELETE:/repository/{obj_id}/access", sender, body)
    authorisation = create_authorisation(f"DELETE:/repository/{obj_id}/access", owner, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.delete(url, data=content).json()
    return r['reply']


def get_ownership(sender, obj_id):
    url = f"http://127.0.0.1:5000/repository/{obj_id}/owner"
    authentication = create_authentication(f"GET:/repository/{obj_id}/owner", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']


def transfer_ownership(sender, obj_id, current_owner, new_owner):
    url = f"http://127.0.0.1:5000/repository/{obj_id}/owner"
    body = {
        'new_owner_public_key': new_owner.public_as_string()
    }
    authentication = create_authentication(f"PUT:/repository/{obj_id}/owner", sender, body)
    authorisation = create_authorisation(f"PUT:/repository/{obj_id}/owner", current_owner, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.put(url, data=content).json()
    return r['reply']


def export_data_object_content(sender, obj_id, owner, destination):
    url = f"http://127.0.0.1:5000/repository/{obj_id}/content"
    authentication = create_authentication(f"GET:/repository/{obj_id}/content", sender)
    authorisation = create_authorisation(f"GET:/repository/{obj_id}/content", owner)
    content = {
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


def get_tags(sender, obj_id):
    url = f"http://127.0.0.1:5000/repository/{obj_id}/tags"
    authentication = create_authentication(f"GET:/repository/{obj_id}/tags", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return r['reply']['tags']


def update_data_object_tags(sender, obj_id, owner, tags):
    body = {
        'tags': []
    }

    # populate the tags array
    for key in tags:
        value = tags[key]

        body['tags'].append({
            'key': key,
            'value': value
        })

    url = f"http://127.0.0.1:5000/repository/{obj_id}/tags"
    authentication = create_authentication(f"PUT:/repository/{obj_id}/tags", sender, body)
    authorisation = create_authorisation(f"PUT:/repository/{obj_id}/tags", owner, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.put(url, data=content).json()
    return r['reply']


def remove_data_object_tags(sender, obj_id, owner, tags):
    body = {
        'tags': tags
    }

    url = f"http://127.0.0.1:5000/repository/{obj_id}/tags"
    authentication = create_authentication(f"DELETE:/repository/{obj_id}/tags", sender, body)
    authorisation = create_authorisation(f"DELETE:/repository/{obj_id}/tags", owner, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.delete(url, data=content).json()
    return r['reply']


def search_data_objects(sender, key_criterion, value_criterion=None):
    body = {
        'key_criterion': key_criterion
    }

    url = f"http://127.0.0.1:5000/repository/?key_criterion={key_criterion}"
    auth_url = f"GET:/repository/?key_criterion={key_criterion}"
    if value_criterion:
        url = f"{url}&value_criterion={value_criterion}"
        auth_url = f"{auth_url}&value_criterion={value_criterion}"
        body['value_criterion'] = value_criterion

    authentication = create_authentication(auth_url, sender, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
    }

    r = requests.get(url, data=content).json()
    return r['reply']['objects']


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
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        # get the descriptor of the data object
        descriptor1 = get_descriptor(self.keys[0], obj_id)
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        # delete the data object
        descriptor2 = delete_data_object(self.keys[0], obj_id, self.keys[1])
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_grant_revoke_access(self):
        logger.info(f"keys[0].iid={self.keys[0].iid}")
        logger.info(f"keys[1].iid={self.keys[1].iid}")
        logger.info(f"keys[2].iid={self.keys[2].iid}")

        ref_obj_id, obj_id = add_data_object(self.keys[0], self.keys[1])
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        permissions = get_access_permissions(self.keys[0], obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 1
        assert self.keys[1].iid in permissions

        reply = grant_access(self.keys[0], obj_id, self.keys[2], self.keys[0])
        assert reply == 'Authorisation failed.'

        permissions = get_access_permissions(self.keys[0], obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 1
        assert permissions[0] == self.keys[1].iid

        reply = grant_access(self.keys[0], obj_id, self.keys[2], self.keys[1])
        assert reply == 'Access granted.'

        permissions = get_access_permissions(self.keys[0], obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 2
        assert self.keys[1].iid in permissions
        assert self.keys[2].iid in permissions

        reply = revoke_access(self.keys[0], obj_id, self.keys[2], self.keys[1])
        assert reply == 'Access revoked.'

        permissions = get_access_permissions(self.keys[0], obj_id)
        logger.info(f"permissions={permissions}")
        assert len(permissions) == 1
        assert self.keys[1].iid in permissions

        descriptor = delete_data_object(self.keys[0], obj_id, self.keys[1])
        logger.info(f"descriptor={descriptor}")
        assert descriptor is not None

    def test_transfer_ownership(self):
        ref_obj_id, obj_id = add_data_object(self.keys[0], self.keys[1])
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        owner_info = get_ownership(self.keys[0], obj_id)
        logger.info(f"owner_info={owner_info}")
        assert owner_info['owner_iid'] == self.keys[1].iid

        reply = transfer_ownership(self.keys[0], obj_id, self.keys[0], self.keys[2])
        assert reply == 'Authorisation failed.'

        reply = transfer_ownership(self.keys[0], obj_id, self.keys[1], self.keys[2])
        logger.info(f"reply={reply}")
        assert reply == f"Ownership of data object '{obj_id}' transferred to '{self.keys[2].iid}'."

        owner_info = get_ownership(self.keys[0], obj_id)
        logger.info(f"owner_info={owner_info}")
        assert owner_info['owner_iid'] == self.keys[2].iid

        descriptor = delete_data_object(self.keys[0], obj_id, self.keys[1])
        logger.info(f"descriptor={descriptor}")
        assert descriptor is None

        descriptor = delete_data_object(self.keys[0], obj_id, self.keys[2])
        logger.info(f"descriptor={descriptor}")
        assert descriptor is not None

    def test_get_data_object(self):
        ref_obj_id, obj_id = add_data_object(self.keys[0], self.keys[1])
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        descriptor1 = get_descriptor(self.keys[0], obj_id)
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        destination = os.path.join(env.wd_path, 'test_copy.dat')
        reply = export_data_object_content(self.keys[0], obj_id, self.keys[0], destination)
        assert reply == 401
        assert not os.path.exists(destination)

        reply = export_data_object_content(self.keys[0], obj_id, self.keys[1], destination)
        assert reply == 200
        assert os.path.isfile(destination)

        descriptor2 = delete_data_object(self.keys[0], obj_id, self.keys[1])
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_fetch_data_object(self):
        ref_obj_id, obj_id = add_data_object(self.keys[0], self.keys[1])
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        descriptor1 = get_descriptor(self.keys[0], obj_id)
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        # create the receiving node
        receiver_wd_path = os.path.join(env.wd_path, 'receiver')
        node = Node('receiver', receiver_wd_path, env.rest_api_address)
        node.initialise_identity(receiver_wd_path)
        node.start_server(env.p2p_server_address)

        peer_address = (env.app_service_p2p_host, env.app_service_p2p_port)

        protocol = DataObjectRepositoryP2PProtocol(node)
        c_hash = protocol.send_fetch(peer_address, 'abcdef')
        assert not c_hash

        c_hash = protocol.send_fetch(peer_address, obj_id)
        assert c_hash

        destination_descriptor_path = os.path.join(receiver_wd_path, node.dor.infix_cache_path, f"{obj_id}.descriptor")
        destination_content_path = os.path.join(receiver_wd_path, node.dor.infix_cache_path, f"{c_hash}.content")
        assert os.path.isfile(destination_descriptor_path)
        assert os.path.isfile(destination_content_path)

        node.stop_server()

        descriptor2 = delete_data_object(self.keys[0], obj_id, self.keys[1])
        logger.info(f"descriptor2={descriptor2}")
        assert descriptor2 is not None
        assert object_to_ordered_list(descriptor1) == object_to_ordered_list(descriptor2)

    def test_add_tag_delete_data_object(self):
        # create the data object
        ref_obj_id, obj_id = add_data_object(self.keys[0], self.keys[1])
        logger.info(f"obj_id: reference={ref_obj_id} actual={obj_id}")
        assert ref_obj_id is not None
        assert obj_id is not None
        assert obj_id == ref_obj_id

        # get tags for that data object
        tags = get_tags(self.keys[0], obj_id)
        logger.info(f"tags={tags}")
        assert tags == {}

        # update tags for that data object
        update_data_object_tags(self.keys[0], obj_id, self.keys[1], {
            'a': '123',
            'b': '567'
        })
        tags = get_tags(self.keys[0], obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 2
        assert 'a' in tags
        assert 'b' in tags
        assert tags['a'] == '123'

        # update tags for that data object
        update_data_object_tags(self.keys[0], obj_id, self.keys[1], {
            'a': '567'
        })
        tags = get_tags(self.keys[0], obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 2
        assert 'a' in tags
        assert 'b' in tags
        assert tags['a'] == '567'

        # remove a tag
        remove_data_object_tags(self.keys[0], obj_id, self.keys[1], ['b'])
        tags = get_tags(self.keys[0], obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 1
        assert 'a' in tags
        assert 'b' not in tags

        # delete the data object
        descriptor = delete_data_object(self.keys[0], obj_id, self.keys[1])
        logger.info(f"descriptor={descriptor}")
        assert descriptor is not None

        tags = get_tags(self.keys[0], obj_id)
        logger.info(f"tags={tags}")
        assert len(tags) == 0

    def test_add_tag_search_delete_data_object(self):
        # create the data object 0
        obj_id0 = add_random_data_object(self.keys[0], self.keys[1], 'test000.dat')
        logger.info(f"obj_id0: {obj_id0}")
        assert obj_id0 is not None

        # update tags for that data object
        update_data_object_tags(self.keys[0], obj_id0, self.keys[1], {
            'hellox': '123',
            'whazzup': '567',
            'a': '123'
        })
        tags0 = get_tags(self.keys[0], obj_id0)
        logger.info(f"tags0={tags0}")
        assert len(tags0) == 3

        # create the data object 1
        obj_id1 = add_random_data_object(self.keys[0], self.keys[1], 'test001.dat')
        logger.info(f"obj_id1: {obj_id1}")
        assert obj_id1 is not None

        # update tags for that data object
        update_data_object_tags(self.keys[0], obj_id1, self.keys[1], {
            'hello': '123',
            'world': '567',
            'a': '124'
        })
        tags1 = get_tags(self.keys[0], obj_id1)
        logger.info(f"tags1={tags1}")
        assert len(tags1) == 3

        # search for data objects
        result = search_data_objects(self.keys[0], "hello")
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id1 in result

        result = search_data_objects(self.keys[0], "hello%")
        logger.info(f"result={result}")
        assert len(result) == 2
        assert obj_id0 in result
        assert obj_id1 in result

        result = search_data_objects(self.keys[0], "hel%")
        logger.info(f"result={result}")
        assert len(result) == 2
        assert obj_id0 in result
        assert obj_id1 in result

        result = search_data_objects(self.keys[0], "whazzup")
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id0 in result

        result = search_data_objects(self.keys[0], "whazzup_")
        logger.info(f"result={result}")
        assert len(result) == 0

        result = search_data_objects(self.keys[0], "a", "123")
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id0 in result

        result = search_data_objects(self.keys[0], "a", "124")
        logger.info(f"result={result}")
        assert len(result) == 1
        assert obj_id1 in result

        result = search_data_objects(self.keys[0], "a", "12%")
        logger.info(f"result={result}")
        assert len(result) == 2
        assert obj_id0 in result
        assert obj_id1 in result

        # delete the data object 0
        descriptor0 = delete_data_object(self.keys[0], obj_id0, self.keys[1])
        logger.info(f"descriptor0={descriptor0}")
        assert descriptor0 is not None

        # delete the data object 1
        descriptor1 = delete_data_object(self.keys[0], obj_id1, self.keys[1])
        logger.info(f"descriptor1={descriptor1}")
        assert descriptor1 is not None

        tags0 = get_tags(self.keys[0], obj_id0)
        logger.info(f"tags0={tags0}")
        assert len(tags0) == 0

        tags1 = get_tags(self.keys[0], obj_id1)
        logger.info(f"tags1={tags1}")
        assert len(tags1) == 0


if __name__ == '__main__':
    unittest.main()
