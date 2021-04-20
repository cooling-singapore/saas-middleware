import logging
import canonicaljson

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


logger = logging.getLogger('hashing')


def hash_file_content(path):
    """
    Hash the content of a given file using SHA256.
    :param path: the path of the file that is to be hashed
    :return: hash
    """
    # use SHA256 for hashing
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

    # read the file in chunks of 64 bytes and update the digest
    with open(path, 'rb') as f:
        data = f.read(64)
        while data:
            digest.update(data)
            data = f.read(64)

    # calculate the hash and return
    result = digest.finalize()
    return result


def hash_json_object(obj):
    """
    Hash a given JSON object. Before hashing the JSON input is encoded as canonical RFC 7159 JSON.
    :param obj: the JSON object that is to be hashed
    :return: hash
    """
    # use SHA256 for hashing
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

    # encode the json input as RFC 7159 JSON as update the digest
    json_input = canonicaljson.encode_canonical_json(obj)
    digest.update(json_input)

    # calculate the hash and return
    result = digest.finalize()
    return result


def hash_string_object(obj):
    """
    Hash a given string.
    :param obj: the string that is to be hashed
    :return: hash
    """
    # use SHA256 for hashing
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(obj.encode('utf-8'))

    # calculate the hash and return
    result = digest.finalize()
    return result


def hash_bytes_object(obj):
    """
    Hash a given byte array.
    :param obj: the byte array that is to be hashed
    :return: hash
    """
    # use SHA256 for hashing
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(obj)

    # calculate the hash and return
    result = digest.finalize()
    return result


def hash_byte_objects(*objects):
    """
    Hash a number of bytes objects.
    :param obj: an arbitrary number of byte arrays to be hashed together
    :return: hash
    """
    # use SHA256 for hashing
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    for obj in objects:
        digest.update(obj)

    # calculate the hash and return
    result = digest.finalize()
    return result
