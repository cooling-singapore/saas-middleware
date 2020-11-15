import logging
import time
import os
import services.utilities as utilities

import cryptography.hazmat.primitives.serialization as serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger('identity')


# TODO: improve
class NoPrivateKeyError(Exception):
    pass


class ECKeyPair:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
        self.iid = utilities.hash_bytes_object(self.public_as_bytes()).hex()
        self.short_iid = "{}...{}".format(self.iid[:4], self.iid[-4:])

    @classmethod
    def create_new(cls):
        private_key = ec.generate_private_key(
            curve=ec.SECP384R1(),
            backend=default_backend()
        )
        return ECKeyPair.from_private_key(private_key)

    @classmethod
    def from_private_key(cls, private_key):
        public_key = private_key.public_key()
        return ECKeyPair(private_key, public_key)

    @classmethod
    def from_private_key_file(cls, path, password):
        with open(path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                data=f.read(),
                password=password.encode('utf-8'),
                backend=default_backend()
            )
            return ECKeyPair.from_private_key(private_key)

    @classmethod
    def from_public_key(cls, public_key):
        return ECKeyPair(None, public_key)

    @classmethod
    def from_public_key_bytes(cls, public_key_bytes):
        public_key = serialization.load_pem_public_key(
            data=public_key_bytes,
            backend=default_backend()
        )
        return ECKeyPair.from_public_key(public_key)

    @classmethod
    def from_public_key_string(cls, public_key_string):
        if '-----BEGIN PUBLIC KEY-----' not in public_key_string:
            public_key_string = '\n'.join(public_key_string[i:i + 64] for i in range(0, len(public_key_string), 64))
            public_key_string = "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----".format(public_key_string)

        return ECKeyPair.from_public_key_bytes(public_key_string.encode('utf-8'))

    @classmethod
    def from_public_key_file(cls, path):
        with open(path, "rb") as f:
            public_key = serialization.load_pem_public_key(
                data=f.read(),
                backend=default_backend()
            )
            return ECKeyPair.from_public_key(public_key)

    def private_as_bytes(self, password):
        if not self.private_key:
            raise NoPrivateKeyError()

        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        )

    def public_as_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def private_as_string(self, password):
        return self.private_as_bytes(password).decode('utf-8')

    def public_as_string(self, truncate=False):
        result = self.public_as_bytes().decode('utf-8')
        if truncate:
            result = result.replace('\n', '')
            result = result[26:-24]
        return result

    def write_private(self, path, password):
        with open(path, 'wb') as f:
            f.write(self.private_as_bytes(password))

    def write_public(self, path):
        with open(path, 'wb') as f:
            f.write(self.public_as_bytes())

    def sign(self, message):
        return self.private_key.sign(message, ec.ECDSA(hashes.SHA256())).hex()

    def verify(self, message, signature):
        try:
            self.public_key.verify(bytes.fromhex(signature), message, ec.ECDSA(hashes.SHA256()))
            return True

        except InvalidSignature:
            return False

    def sign_authentication_token(self, url, body, files=[]):
        file_hashes = []
        for file in files:
            file_hashes.append(utilities.hash_file_content(file))
        file_hashes.sort()
        # logger.info("file_hashes={}".format(file_hashes))
        # logger.info("url={}".format(utilities.hash_string_object(url).hex()))
        # logger.info("body={}".format(utilities.hash_json_object(body).hex()))
        # logger.info("public_key={}".format(utilities.hash_string_object(self.public_as_string(truncate=True)).hex()))

        token = utilities.hash_string_object(url).hex()
        token += utilities.hash_json_object(body).hex()
        token += utilities.hash_string_object(self.public_as_string(truncate=True)).hex()
        for file_hash in file_hashes:
            token += file_hash.hex()
            # logger.info("file_hash={}".format(file_hash.hex()))

        token = utilities.hash_string_object(token)
        # logger.info("token={}".format(token.hex()))

        return self.sign(token)

    def verify_authentication_token(self, signature, url, body, files={}):
        file_hashes = []
        for label in files:
            file_hashes.append(utilities.hash_file_content(files[label]))
        file_hashes.sort()
        # logger.info("file_hashes={}".format(file_hashes))
        # logger.info("url={}".format(utilities.hash_string_object(url).hex()))
        # logger.info("body={}".format(utilities.hash_json_object(body).hex()))
        # logger.info("public_key={}".format(utilities.hash_string_object(self.public_as_string(truncate=True)).hex()))

        token = utilities.hash_string_object(url).hex()
        token += utilities.hash_json_object(body).hex()
        token += utilities.hash_string_object(self.public_as_string(truncate=True)).hex()
        for file_hash in file_hashes:
            token += file_hash.hex()
            # logger.info("file_hash={}".format(file_hash.hex()))

        token = utilities.hash_string_object(token)
        # logger.info("token={}".format(token.hex()))

        return self.verify(token, signature)

    def sign_authorisation_token(self, url, body, timeslot_length=5):
        # determine current time slot
        slot = int(time.time() / timeslot_length)

        # logger.info("url={}".format(utilities.hash_string_object(url).hex()))
        # logger.info("body={}".format(utilities.hash_json_object(body).hex()))
        # logger.info("slot={}".format(utilities.hash_bytes_object(bytes(slot)).hex()))
        # logger.info("public_key={}".format(utilities.hash_string_object(self.public_as_string(truncate=True)).hex()))

        token = utilities.hash_string_object(url).hex()
        token += utilities.hash_json_object(body).hex()
        token += utilities.hash_bytes_object(bytes(slot)).hex()
        token += utilities.hash_string_object(self.public_as_string(truncate=True)).hex()
        token = utilities.hash_string_object(token)
        # logger.info("token={}".format(token.hex()))

        return self.sign(token)

    def verify_authorisation_token(self, signature, url, body={}, timeslot_length=5):
        # determine time slots (we allow for some variation before and after)
        ref = int(time.time() / timeslot_length)
        slots = [ref - 1, ref, ref + 1]

        for slot in slots:
            # logger.info("url={}".format(utilities.hash_string_object(url).hex()))
            # logger.info("body={}".format(utilities.hash_json_object(body).hex()))
            # logger.info("slot={}".format(utilities.hash_bytes_object(bytes(slot)).hex()))
            # logger.info("public_key={}".format(utilities.hash_string_object(self.public_as_string(truncate=True)).hex()))

            token = utilities.hash_string_object(url).hex()
            token += utilities.hash_json_object(body).hex()
            token += utilities.hash_bytes_object(bytes(slot)).hex()
            token += utilities.hash_string_object(self.public_as_string(truncate=True)).hex()
            token = utilities.hash_string_object(token)
            # logger.info("token={}".format(token.hex()))

            if self.verify(token, signature):
                return True

        # no valid signature for any of the eligible timeslots
        return False
