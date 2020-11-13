import time
import logging
import json
import canonicaljson

from cryptography.hazmat.primitives import hashes

logger = logging.getLogger('utilities')


def get_timestamp_now():
    return int(round(time.time() * 1000))


def hash_file_content(path):
    # use SHA256 for hashing
    digest = hashes.Hash(hashes.SHA256())

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
    # use SHA256 for hashing
    digest = hashes.Hash(hashes.SHA256())

    # encode the json input as RFC 7159 JSON as update the digest
    json_input = canonicaljson.encode_canonical_json(obj)
    digest.update(json_input)

    # calculate the hash and return
    result = digest.finalize()
    return result


def hash_string_object(obj):
    # use SHA256 for hashing
    digest = hashes.Hash(hashes.SHA256())
    digest.update(obj.encode('utf-8'))

    # calculate the hash and return
    result = digest.finalize()
    return result


def hash_bytes_object(obj):
    # use SHA256 for hashing
    digest = hashes.Hash(hashes.SHA256())
    digest.update(obj)

    # calculate the hash and return
    result = digest.finalize()
    return result


def dump_json_to_file(json_input, destination_path):
    with open(destination_path, 'w') as f:
        json.dump(json_input, f, indent=4, sort_keys=True)
