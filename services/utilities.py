import time
import os
import logging
import subprocess
import json
import canonicaljson
import threading
import socket
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

import cryptography.hazmat.primitives.serialization as serialization


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


def create_private_key():
    return ec.generate_private_key(
        curve=ec.SECP384R1(),
        backend=default_backend()
    )


def deserialize_private_key(data, password):
    return serialization.load_pem_private_key(
        data=data,
        password=password,
        backend=default_backend()
    )


def serialize_private_key(private_key, password):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password)
    )


def deserialize_public_key(data):
    return serialization.load_pem_public_key(
        data=data,
        backend=default_backend()
    )


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
