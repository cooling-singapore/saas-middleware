import json
import requests
import os
import logging
import time
import socket

from services.node import SecureMessenger

from services.eckeypair import ECKeyPair

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('Test')

path = "/Users/heikoaydt/Desktop/saas_env/testing"


def create_keys(password):
    k1_path = os.path.join(path, "key1.pem")
    k2_path = os.path.join(path, "key2.pem")
    k3_path = os.path.join(path, "key3.pem")

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


key1, key2, key3 = create_keys("test")
logger.info("key1={} iid1={}".format(key1.public_as_string(truncate=True), key1.iid))
logger.info("key2={} iid1={}".format(key2.public_as_string(truncate=True), key2.iid))
logger.info("key3={} iid1={}".format(key3.public_as_string(truncate=True), key3.iid))


def create_authentication(url, body, auth_key, attachment_path=None):
    return {
        'public_key': auth_key.public_as_string(truncate=True),
        'signature': auth_key.sign_authentication_token(url, body, [attachment_path] if attachment_path else [])
    }


def create_authorisation(url, body, auth_key):
    return {
        'public_key': auth_key.public_as_string(truncate=True),
        'signature': auth_key.sign_authorisation_token(url, body)
    }


def test_authentication():
    url = "/repository/345345345lk3j45345ef3f34r3984r"
    params = {
        'a': 'asdasdas',
        'f': 2343
    }
    file_path = os.path.join(path, 'data.tar.gz')

    signature = key1.sign_authentication_token(url, params, [file_path])

    print(key1.verify_authentication_token(signature, url, params, {'label': file_path}))


def test_authorisation():
    url = "/repository/345345345lk3j45345ef3f34r3984r"
    params = {
        'a': 'asdasdas',
        'f': 2343
    }

    signature = key1.sign_authorisation_token(url, params)

    print(key1.verify_authorisation_token(signature, url, params))

    time.sleep(7)

    print(key1.verify_authorisation_token(signature, url, params))


def test_add_data_object():
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
        'owner_public_key': key2.public_as_string(truncate=True)
    }

    file_path = os.path.join(path, 'data.tar.gz')

    authentication = create_authentication('POST:/', body, key1, file_path)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    with open(file_path, 'rb') as f:
        r = requests.post(url, data=content, files={'attachment': f.read()})
        print(r.content)


def test_get_header():
    url = "http://127.0.0.1:5000/repository/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/header"
    body = {}
    authentication = create_authentication(
        'GET:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/header', body, key1)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content)
    print(r.content)


def test_get_content_export():
    url = "http://127.0.0.1:5000/repository/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/content"
    body = {
        'type': 'export'
    }
    authentication = create_authentication(
        'GET:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/content', body, key1)
    authorisation = create_authorisation(
        'GET:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/content', body, key2)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    local_filename = os.path.join(path, "6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16_1.tar.gz")
    with requests.get(url, data=content, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)


def test_get_content_internal():
    url = "http://127.0.0.1:5000/repository/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/content"
    body = {
        'type': 'internal'
    }
    authentication = create_authentication(
        'GET:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/content', body, key1)
    authorisation = create_authorisation(
        'GET:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/content', body, key2)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.get(url, data=content)
    print(r.content)

def test_get_content_fetch():
    # get the last known address of the custodian
    custodian_address = ('127.0.0.1', 4000)
    logger.info("address={}".format(custodian_address))

    # create messenger
    peer = socket.create_connection(custodian_address)
    messenger = SecureMessenger(peer)
    peer = messenger.handshake(key2)
    logger.info("connected to peer '{}'".format(peer.iid))

    response = messenger.request({
        'request': 'fetch',
        'obj_id': '6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16'
    })
    logger.info("response received: {}".format(response))

    destination_path = os.path.join(path, "6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16_2.tar.gz")
    if response['reply'] == 'found':
        messenger.receive_attachment(destination_path)

    return destination_path


def test_get_owner():
    url = "http://127.0.0.1:5000/repository/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/owner"
    body = {}
    authentication = create_authentication(
        'GET:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/owner', body, key1)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content)
    print(r.content)


def test_get_header_not_found():
    url = "http://127.0.0.1:5000/repository/7af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/header"
    body = {}
    authentication = create_authentication(
        'GET:/7af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/header', body, key1)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content)
    print(r.content)


def test_delete_data_object_failure():
    url = "http://127.0.0.1:5000/repository/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16"
    body = {}
    authentication = create_authentication('DELETE:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16',
                                           body, key1)
    authorisation = create_authorisation('DELETE:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16',
                                         body, key1)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.delete(url, data=content)
    print(r.content)


def test_delete_data_object_success():
    url = "http://127.0.0.1:5000/repository/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16"
    body = {}
    authentication = create_authentication('DELETE:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16',
                                           body, key1)
    authorisation = create_authorisation('DELETE:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16',
                                         body, key2)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.delete(url, data=content)
    print(r.content)


def test_grant_access_permission():
    url = "http://127.0.0.1:5000/repository/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/access"
    body = {
        'user_public_key':key3.public_as_string(truncate=True)
    }
    authentication = create_authentication('POST:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/access',
                                           body, key1)
    authorisation = create_authorisation('POST:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/access',
                                         body, key2)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.post(url, data=content)
    print(r.content)

def test_revoke_access_permission():
    url = "http://127.0.0.1:5000/repository/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/access"
    body = {
        'user_public_key':key3.public_as_string(truncate=True)
    }
    authentication = create_authentication('DELETE:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/access',
                                           body, key1)
    authorisation = create_authorisation('DELETE:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/access',
                                         body, key2)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.delete(url, data=content)
    print(r.content)

def test_get_access():
    url = "http://127.0.0.1:5000/repository/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/access"
    body = {}
    authentication = create_authentication(
        'GET:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/access', body, key1)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content)
    print(r.content)


def test_transfer_ownership_failure():
    url = "http://127.0.0.1:5000/repository/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/owner"
    body = {
        'new_owner_public_key': key3.public_as_string(truncate=True)
    }
    authentication = create_authentication('PUT:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/owner',
                                           body, key1)
    authorisation = create_authorisation('PUT:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/owner',
                                         body, key1)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.put(url, data=content)
    print(r.content)

def test_transfer_ownership_success():
    url = "http://127.0.0.1:5000/repository/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/owner"
    body = {
        'new_owner_public_key': key3.public_as_string(truncate=True)
    }
    authentication = create_authentication('PUT:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/owner',
                                           body, key1)
    authorisation = create_authorisation('PUT:/6af981f1d684418d73190591f8c4b9d57aa4ab0a8371005dcb698fb585236b16/owner',
                                         body, key2)

    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication),
        'authorisation': json.dumps(authorisation)
    }

    r = requests.put(url, data=content)
    print(r.content)

# test_authentication()
# test_authorisation()
test_add_data_object()
# test_get_content_export()
# test_get_content_internal()
# test_get_content_fetch()
# test_get_header()
# test_get_header_not_found()
test_delete_data_object_failure()
test_delete_data_object_success()
# test_add_data_object()
# test_get_owner()
# test_get_access()
# test_grant_access_permission()
# test_get_access()
# test_revoke_access_permission()
# test_get_access()
# test_get_owner()
# test_transfer_ownership_failure()
# test_get_owner()
# test_transfer_ownership_success()
# test_get_owner()
