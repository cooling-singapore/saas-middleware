import logging
import os

import pytest

from saas.core.exceptions import SaaSRuntimeException
from saas.core.schemas import GithubCredentials, SSHCredentials
from saas.core.keystore import Keystore
from saas.core.eckeypair import ECKeyPair
from saas.core.rsakeypair import RSAKeyPair
from saas.core.logging import Logging


Logging.initialise(level=logging.DEBUG)
logger = Logging.get(__name__)


@pytest.fixture()
def ec_keypair():
    return ECKeyPair.create_new()


@pytest.fixture()
def rsa_keypair():
    return RSAKeyPair.create_new()


@pytest.fixture()
def logging():
    yield
    Logging.remove_all_handlers()


def test_ec_serialisation(temp_directory, ec_keypair):
    password = 'test'

    pubkey_path = os.path.join(temp_directory, 'pubkey.pem')
    prvkey_path = os.path.join(temp_directory, 'prvkey.pem')
    ec_keypair.write_public(pubkey_path)
    ec_keypair.write_private(prvkey_path, password)

    pubkey = ec_keypair.public_key
    pubkey_bytes = ec_keypair.public_as_bytes()
    pubkey_string0 = ec_keypair.public_as_string(truncate=False)
    pubkey_string1 = ec_keypair.public_as_string(truncate=True)
    result0 = ECKeyPair.from_public_key(pubkey)
    result1 = ECKeyPair.from_public_key_bytes(pubkey_bytes)
    result2 = ECKeyPair.from_public_key_string(pubkey_string0)
    result3 = ECKeyPair.from_public_key_string(pubkey_string1)
    result4 = ECKeyPair.from_public_key_file(pubkey_path)

    assert(result0.private_key is None)
    assert(result1.private_key is None)
    assert(result2.private_key is None)
    assert(result3.private_key is None)
    assert(result4.private_key is None)

    assert(result0.iid == ec_keypair.iid)
    assert(result1.iid == ec_keypair.iid)
    assert(result2.iid == ec_keypair.iid)
    assert(result3.iid == ec_keypair.iid)
    assert(result4.iid == ec_keypair.iid)

    private_key = ec_keypair.private_key
    prvkey_string0 = ec_keypair.private_as_string(password, truncate=False)
    prvkey_string1 = ec_keypair.private_as_string(password, truncate=True)
    prvkey_string2 = ec_keypair.private_as_string(truncate=False)
    prvkey_string3 = ec_keypair.private_as_string(truncate=True)

    result0 = ECKeyPair.from_private_key_file(prvkey_path, password)
    result1 = ECKeyPair.from_private_key(private_key)
    result2 = ECKeyPair.from_private_key_string(prvkey_string0, password)
    result3 = ECKeyPair.from_private_key_string(prvkey_string1, password)
    result4 = ECKeyPair.from_private_key_string(prvkey_string2)
    result5 = ECKeyPair.from_private_key_string(prvkey_string3)

    assert(result0.iid == ec_keypair.iid)
    assert(result1.iid == ec_keypair.iid)
    assert(result2.iid == ec_keypair.iid)
    assert(result3.iid == ec_keypair.iid)
    assert(result4.iid == ec_keypair.iid)
    assert(result5.iid == ec_keypair.iid)


def test_ec_signing(ec_keypair):
    message0 = 'test0'.encode('utf-8')
    message1 = 'test1'.encode('utf-8')

    signature0 = ec_keypair.sign(message0)
    assert(ec_keypair.verify(message0, signature0))
    assert(not ec_keypair.verify(message1, signature0))


def test_rsa_serialisation(temp_directory, rsa_keypair):
    password = 'test'

    pubkey_path = os.path.join(temp_directory, 'pubkey.pem')
    prvkey_path = os.path.join(temp_directory, 'prvkey.pem')
    rsa_keypair.write_public(pubkey_path)
    rsa_keypair.write_private(prvkey_path, password)

    pubkey = rsa_keypair.public_key
    pubkey_bytes = rsa_keypair.public_as_bytes()
    pubkey_string0 = rsa_keypair.public_as_string(truncate=False)
    pubkey_string1 = rsa_keypair.public_as_string(truncate=True)
    result0 = RSAKeyPair.from_public_key(pubkey)
    result1 = RSAKeyPair.from_public_key_bytes(pubkey_bytes)
    result2 = RSAKeyPair.from_public_key_string(pubkey_string0)
    result3 = RSAKeyPair.from_public_key_string(pubkey_string1)
    result4 = RSAKeyPair.from_public_key_file(pubkey_path)

    assert(result0.private_key is None)
    assert(result1.private_key is None)
    assert(result2.private_key is None)
    assert(result3.private_key is None)
    assert(result4.private_key is None)

    assert(result0.iid == rsa_keypair.iid)
    assert(result1.iid == rsa_keypair.iid)
    assert(result2.iid == rsa_keypair.iid)
    assert(result3.iid == rsa_keypair.iid)
    assert(result4.iid == rsa_keypair.iid)

    private_key = rsa_keypair.private_key
    prvkey_string0 = rsa_keypair.private_as_string(password, truncate=False)
    prvkey_string1 = rsa_keypair.private_as_string(password, truncate=True)
    prvkey_string2 = rsa_keypair.private_as_string(truncate=False)
    prvkey_string3 = rsa_keypair.private_as_string(truncate=True)

    result0 = RSAKeyPair.from_private_key_file(prvkey_path, password)
    result1 = RSAKeyPair.from_private_key(private_key)
    result2 = RSAKeyPair.from_private_key_string(prvkey_string0, password)
    result3 = RSAKeyPair.from_private_key_string(prvkey_string1, password)
    result4 = RSAKeyPair.from_private_key_string(prvkey_string2)
    result5 = RSAKeyPair.from_private_key_string(prvkey_string3)

    assert(result0.iid == rsa_keypair.iid)
    assert(result1.iid == rsa_keypair.iid)
    assert(result2.iid == rsa_keypair.iid)
    assert(result3.iid == rsa_keypair.iid)
    assert(result4.iid == rsa_keypair.iid)
    assert(result5.iid == rsa_keypair.iid)


def test_rsa_signing(rsa_keypair):
    message0 = 'test0'.encode('utf-8')
    message1 = 'test1'.encode('utf-8')

    signature0 = rsa_keypair.sign(message0)
    assert(rsa_keypair.verify(message0, signature0))
    assert(not rsa_keypair.verify(message1, signature0))


def test_rsa_encryption(rsa_keypair):
    plaintext = "test"

    encrypted = rsa_keypair.encrypt(plaintext.encode('utf-8'))
    decrypted = rsa_keypair.decrypt(encrypted).decode('utf-8')

    assert(plaintext == decrypted)


def test_create_and_load(temp_directory):
    keystore = Keystore.create(temp_directory, 'name', 'email', 'password')
    assert(keystore is not None)
    assert(keystore.identity.name == 'name')
    assert(keystore.identity.email == 'email')
    assert(keystore.identity.nonce == 1)

    keystore_id = keystore.identity.id
    keystore_path = os.path.join(temp_directory, f"{keystore_id}.json")
    assert(os.path.isfile(keystore_path))

    keystore = Keystore.load(keystore_path, 'password')
    assert(keystore is not None)
    assert(keystore.identity.id == keystore_id)
    assert(keystore.identity.name == 'name')
    assert(keystore.identity.email == 'email')
    assert(keystore.identity.nonce == 1)


def test_update(temp_directory):
    keystore = Keystore.create(temp_directory, 'name', 'email', 'password')
    keystore_id = keystore.identity.id
    assert(keystore.identity.name == 'name')
    assert(keystore.identity.email == 'email')

    name = 'name2'
    email = 'email2'

    # perform update
    identity = keystore.update_profile(name=name, email=email)
    logger.info(f"signature={identity.signature}")
    assert(identity.signature is not None)
    assert(keystore.identity.name == name)
    assert(keystore.identity.email == email)

    # verify authenticity
    assert(identity.verify_integrity())

    keystore = Keystore.load(os.path.join(temp_directory, f"{keystore_id}.json"), 'password')
    assert(keystore is not None)
    assert(keystore.identity.id == keystore_id)
    assert(keystore.identity.name == name)
    assert(keystore.identity.email == email)
    assert(keystore.identity.nonce == 2)


def test_add_get_object_key(temp_directory):
    keystore = Keystore.create(temp_directory, 'name', 'email', 'password')
    assert(keystore.identity.name == 'name')
    assert(keystore.identity.email == 'email')

    obj_id = 'obj1'
    obj_key = 'key1'

    keystore.content_keys.update(obj_id, obj_key)
    assert(keystore.content_keys.get(obj_id) == obj_key)

    keystore.sync()

    keystore = Keystore.load(os.path.join(temp_directory, f"{keystore.identity.id}.json"), 'password')
    assert(keystore.identity.name == 'name')
    assert(keystore.identity.email == 'email')

    assert(keystore.content_keys.get(obj_id) == obj_key)


def test_add_credentials(temp_directory):
    url = 'https://github.com/cooling-singapore/saas-middleware'
    login = 'johndoe'
    personal_access_token = 'token'
    host = '192.168.0.1'
    key = '<<<key here>>>'

    keystore = Keystore.create(temp_directory, 'name', 'email', 'password')
    assert(keystore.identity.name == 'name')
    assert(keystore.identity.email == 'email')

    keystore.github_credentials.update(url, GithubCredentials(login=login,
                                                              personal_access_token=personal_access_token))

    keystore.ssh_credentials.update('my-remote-machine', SSHCredentials(host=host, login=login, key=key,
                                                                        key_is_password=True))
    keystore.sync()

    keystore = Keystore.load(os.path.join(temp_directory, f"{keystore.identity.id}.json"), 'password')
    c = keystore.github_credentials.get(url)
    print(c)
    assert(c is not None)
    assert(c.login == login)
    assert(c.personal_access_token == personal_access_token)

    c = keystore.ssh_credentials.get('my-remote-machine')
    print(c)
    assert(c is not None)
    assert(c.host == host)
    assert(c.login == login)
    assert(c.key == key)


def test_defaults(logging):
    Logging.initialise()
    logger = Logging.get('test')

    logger.info("you can see me!")
    logger.debug("you should not be able to see me!")


def test_log_to_separate_file(logging, temp_directory):
    default_log_path = os.path.join(temp_directory, 'log.default')
    custom_log_path = os.path.join(temp_directory, 'log.custom')

    Logging.initialise(log_path=default_log_path)

    default = Logging.get('default_logger')
    custom = Logging.get('custom_logger', custom_log_path=custom_log_path)

    default.info("this should go into the default log file")
    custom.info("this should go into the default log file AND the custom log file")

    with open(default_log_path, 'r') as f:
        default_lines = f.readlines()
        print(default_lines)
    assert(len(default_lines) == 2)

    with open(custom_log_path, 'r') as f:
        custom_lines = f.readlines()
        print(custom_lines)
    assert(len(custom_lines) == 1)


def test_rollover(logging, temp_directory):
    log_path0 = os.path.join(temp_directory, 'log')
    log_path1 = os.path.join(temp_directory, 'log.1')
    log_path2 = os.path.join(temp_directory, 'log.2')

    Logging.initialise(log_path=log_path0, max_bytes=80)

    logger = Logging.get('logger')
    assert(os.path.isfile(log_path0))
    assert(not os.path.isfile(log_path1))
    assert(not os.path.isfile(log_path2))

    logger.info('msg')
    assert(os.path.isfile(log_path0))
    assert(not os.path.isfile(log_path1))
    assert(not os.path.isfile(log_path2))

    logger.info('msg')
    assert(os.path.isfile(log_path0))
    assert(os.path.isfile(log_path1))
    assert(not os.path.isfile(log_path2))

    logger.info('msg')
    assert(os.path.isfile(log_path0))
    assert(os.path.isfile(log_path1))
    assert(os.path.isfile(log_path2))


def test_json_incompatible_exception():
    class SomeClass:
        pass

    instance = SomeClass()

    # create an exception with details that cannot be JSON encoded. it should still work but everything in details
    # is turned into a string.
    e = SaaSRuntimeException('something happened...', details={
        'a': 34,
        'b': 4.5,
        'c': 'sdfs',
        'd': {
            'd1': 'sd'
        },
        'e': instance
    })

    for k, v in e.details.items():
        assert isinstance(v, str)

def test_logging_aws_cloudwatch_integration(logging):
    # Before running this test, ensure that [default] in credentials file is available in .aws directory
    # Initialize logging with AWS CloudWatch enabled
    Logging.initialise(log_to_aws=True)

    # Get a logger instance
    logger = Logging.get('test_logger')

    # Log a message
    logger.info("This message should be logged to AWS CloudWatch")

    # Assert that the message was logged to CloudWatch
    # You can check the CloudWatch logs in the AWS Management Console
    # to verify that the message was indeed logged.