"""
This module contains the code for Elliptic Curve (EC) Key Pair functionality which is at the core of the identity
concept used by the Saas Middleware.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging
import time
import canonicaljson
import cryptography.hazmat.primitives.serialization as serialization

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


logger = logging.getLogger('ECKeyPair')


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


class ECKeyPair:
    """
    ECKeyPair encapsulates the functionality for Elliptic Curve (EC) key pairs. It provides a number of convenience
    methods to create a ECKeyPair instance as well as for (de)serialisation of keys. A EC key pair consists of a
    private key and a public key whereby the public key can be derived from the private key. ECKeyPair provides also
    a number of methods for creating and verifying signatures and authentication/authorisation tokens.
    """
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
        self.iid = hash_bytes_object(self.public_as_bytes()).hex()
        self.short_iid = f"{self.iid[:4]}...{self.iid[-4:]}"

    @classmethod
    def create_new(cls):
        """
        Creates an ECKeyPair instance with a randomly generated private key.
        :return: ECKeyPair instance
        """
        private_key = ec.generate_private_key(
            curve=ec.SECP384R1(),
            backend=default_backend()
        )
        return ECKeyPair.from_private_key(private_key)

    @classmethod
    def from_private_key(cls, private_key):
        """
        Creates an ECKeyPair instance based on a given private key.
        :param private_key:
        :return: ECKeyPair instance
        """
        public_key = private_key.public_key()
        return ECKeyPair(private_key, public_key)

    @classmethod
    def from_private_key_file(cls, path, password):
        """
        Creates an ECKeyPair instance by reading a private key from a PEM file.
        :param path: the path to the file containing the private key
        :param password: the password used to protect the private key
        :return: ECKeyPair instance
        """
        with open(path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                data=f.read(),
                password=password.encode('utf-8'),
                backend=default_backend()
            )
            return ECKeyPair.from_private_key(private_key)

    @classmethod
    def from_public_key(cls, public_key):
        """
        Creates an ECKeyPair instance based on a given public key. Note that the private key cannot be derived
        from the public key. An ECKeyPair instance generated this way cannot be used for creating signatures, only
        for verification.
        :param public_key: the public key
        :return: ECKeyPair instance
        """
        return ECKeyPair(None, public_key)

    @classmethod
    def from_public_key_bytes(cls, public_key_bytes):
        """
        Creates an ECKeyPair instance based on a given public key presented as byte array. Note that the private key
        cannot be derived from the public key. An ECKeyPair instance generated this way cannot be used for creating
        signatures, only for verification.
        :param public_key_bytes: the public key as byte array
        :return: ECKeyPair instance
        """
        public_key = serialization.load_pem_public_key(
            data=public_key_bytes,
            backend=default_backend()
        )
        return ECKeyPair.from_public_key(public_key)

    @classmethod
    def from_public_key_string(cls, public_key_string):
        """
        Creates an ECKeyPair instance based on a given public key presented as string. Note that the private key
        cannot be derived from the public key. An ECKeyPair instance generated this way cannot be used for creating
        signatures, only for verification.
        :param public_key_string: the public key as string (full-length or truncated)
        :return: ECKeyPair instance
        """
        if '-----BEGIN PUBLIC KEY-----' not in public_key_string:
            public_key_string = '\n'.join(public_key_string[i:i + 64] for i in range(0, len(public_key_string), 64))
            public_key_string = f"-----BEGIN PUBLIC KEY-----\n{public_key_string}\n-----END PUBLIC KEY-----"

        return ECKeyPair.from_public_key_bytes(public_key_string.encode('utf-8'))

    @classmethod
    def from_public_key_file(cls, path):
        """
        Creates an ECKeyPair instance by reading a public key from a PEM file. Public keys are not password protected,
        so password is required. An ECKeyPair instance generated this way cannot be used for creating signatures, only
        for verification.
        :param path: the path to the file containing the public key
        :return: ECKeyPair instance
        """
        with open(path, "rb") as f:
            public_key = serialization.load_pem_public_key(
                data=f.read(),
                backend=default_backend()
            )
            return ECKeyPair.from_public_key(public_key)

    def private_as_bytes(self, password):
        """
        Serialises the private key and returns it as byte array (or None in case this ECKeyPair instance does not
        have a private key).
        :param password: the password to protect the private key
        :return: byte array representing the password-protected private key or None if no private key is available
        """
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        ) if self.private_key else None

    def public_as_bytes(self):
        """
        Serialises the public key and returns it as byte array.
        :return: byte array representing the public key
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def private_as_string(self, password):
        """
        Serialises the private key and returns it as string (or None in case this ECKeyPair instance does not
        have a private key).
        :param password: the password to protect the private key
        :return: string representing of the private key or None if no private key is available
        """
        return self.private_as_bytes(password).decode('utf-8') if self.private_key else None

    def public_as_string(self, truncate=True):
        """
        Serialises the public key and returns it as string. If truncate=True, the PEM prefix and suffix is removed
        as well as all white space characters.
        :param truncate: indicates whether or not to create a truncated string (default: False)
        :return: string representing the public key
        """
        result = self.public_as_bytes().decode('utf-8')
        if truncate:
            result = result.replace('\n', '')
            result = result[26:-24]
        return result

    def write_private(self, path, password):
        """
        Writes the private key into a file.
        :param path: the path where to store the private key
        :param password: the password used to protected the private key
        :return: None
        """
        with open(path, 'wb') as f:
            f.write(self.private_as_bytes(password))

    def write_public(self, path):
        """
        Writes the public key into a file.
        :param path: the path where to store the public key
        :return: None
        """
        with open(path, 'wb') as f:
            f.write(self.public_as_bytes())

    def sign(self, message):
        """
        Sign a message using the private key.
        :param message: the message that has to be signed
        :return: the signature
        """
        return self.private_key.sign(message, ec.ECDSA(hashes.SHA256())).hex()

    def verify(self, message, signature):
        """
        Verifies the signature for a given message using the public key.
        :param message: the message that has been used for signing
        :param signature: the signature
        :return: True of False depending on whether the signature is valid
        """
        try:
            self.public_key.verify(bytes.fromhex(signature), message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    # TODO: Reconsider the sign/verify authentication/authorisation methods, i.e., the way they work, how they are
    #       supposed to be used and what parameters they need.
    def sign_authentication_token(self, url, body=None, files=None):
        """
        Signs an authentication token using the private key. A authentication token includes a series of information
        that MUST be known to both - sender and receiver of a message - at the time a request is made. The information
        should very specific to the context and not known in advance (to avoid an attack whereby signatures are created
        in advance). For this purpose, the authentication token is based on a url, body and (optional) files contents.
        :param url: a string (e.g., representing the REST API endpoint used for the request)
        :param body: a json object containing additional information (e.g., parameters used for making the request)
        endpoint)
        :param files: files that may be part of the request (e.g., attachment for a POST request)
        :return: the signature
        """
        file_hashes = []
        if files:
            for file in files:
                file_hashes.append(hash_file_content(file))
            file_hashes.sort()

        # logger.info("sign_authentication_token\turl={}".format(url))
        # logger.info("sign_authentication_token\tbody={}".format(body))
        # logger.info("sign_authentication_token\tfiles={}".format(files))
        #
        # logger.info("sign_authentication_token\tH(url)={}".format(hash_string_object(url).hex()))
        token = hash_string_object(url).hex()

        # logger.info("sign_authentication_token\tH(public_key)={}".format(hash_string_object(self.public_as_string()).hex()))
        token += hash_string_object(self.public_as_string()).hex()

        if body:
            # logger.info("sign_authentication_token\tH(body)={}".format(hash_json_object(body).hex()))
            token += hash_json_object(body).hex()

        for file_hash in file_hashes:
            # logger.info("sign_authentication_token\tH(file_hash)={}".format(file_hash.hex()))
            token += file_hash.hex()

        token = hash_string_object(token)
        # logger.info("sign_authentication_token\ttoken={}".format(token.hex()))

        return self.sign(token)

    def verify_authentication_token(self, signature, url, body=None, files=None):
        """
        Verifies the signature of an authentication token. This method should be called by the receiver of a request.
        The information needed to create the authentication token should be known to the receiver of the request at
        the time the request is made in order to recreate the exact same token that has been used by the sender.
        :param signature: the signature that is to be verified
        :param url: a string (e.g., representing the REST API endpoint used for the request)
        :param body: a json object containing additional information (e.g., parameters used for making the request)
        endpoint)
        :param files: files that may be part of the request (e.g., attachment for a POST request)
        :return: True of False depending on whether the signature is valid
        """
        file_hashes = []
        if files:
            for label in files:
                file_hashes.append(hash_file_content(files[label]))
            file_hashes.sort()

        # logger.info("verify_authentication_token\turl={}".format(url))
        # logger.info("verify_authentication_token\tbody={}".format(body))
        # logger.info("verify_authentication_token\tfiles={}".format(files))
        #
        # logger.info("verify_authentication_token\tH(url)={}".format(hash_string_object(url).hex()))
        token = hash_string_object(url).hex()

        # logger.info("verify_authentication_token\tH(public_key)={}".format(hash_string_object(self.public_as_string()).hex()))
        token += hash_string_object(self.public_as_string()).hex()

        if body:
            # logger.info("verify_authentication_token\tH(body)={}".format(hash_json_object(body).hex()))
            token += hash_json_object(body).hex()

        for file_hash in file_hashes:
            # logger.info("verify_authentication_token\tH(file_hash)={}".format(file_hash.hex()))
            token += file_hash.hex()

        token = hash_string_object(token)
        # logger.info("verify_authentication_token\ttoken={}".format(token.hex()))

        return self.verify(token, signature)

    def sign_authorisation_token(self, url, body=None, precision=5):
        """
        Signs an authorisation token using the private key. An authorisation token includes a series of information
        that MUST be known to both - sender and receiver of a message - at the time a request is made. The information
        should very specific to the context and not known in advance (to avoid an attack whereby signatures are created
        in advance). For this purpose, the authentication token is based on a url and body. In addition, a timeslot is
        determined. A timeslot is basically a timestamp with a certain precision (e.g., 5 seconds).
        :param url: a string (e.g., representing the REST API endpoint used for the request)
        :param body: a json object containing additional information (e.g., parameters used for making the request)
        endpoint)
        :param precision: the length of a duration in seconds (default: 5)
        :return: the signature
        """
        slot = int(time.time() / precision)

        # logger.info("sign_authorisation_token\tH(url)={}".format(hash_json_object(url).hex()))
        token = hash_string_object(url).hex()

        if body:
            # logger.info("sign_authorisation_token\tH(body)={}".format(hash_json_object(body).hex()))
            token += hash_json_object(body).hex()

        # logger.info("sign_authorisation_token\tH(bytes(slot))={}".format(hash_bytes_object(bytes(slot)).hex()))
        token += hash_bytes_object(bytes(slot)).hex()

        # logger.info("sign_authorisation_token\tH(self.public_as_string())={}".format(hash_string_object(self.public_as_string()).hex()))
        token += hash_string_object(self.public_as_string()).hex()

        token = hash_string_object(token)
        # logger.info("sign_authorisation_token\ttoken={}".format(token.hex()))

        return self.sign(token)

    def verify_authorisation_token(self, signature, url, body=None, precision=5):
        """
        Verifies the signature of an authorisation token. This method should be called by the receiver of a request.
        The information needed to create the authentication token should be known to the receiver of the request at
        the time the request is made in order to recreate the exact same token that has been used by the sender. The
        authorisation token is tied to a timeslot. For verification, the current time slot +/- 1 is considered as
        acceptable.
        :param signature: the signature that is to be verified
        :param url: a string (e.g., representing the REST API endpoint used for the request)
        :param body: a json object containing additional information (e.g., parameters used for making the request)
        endpoint)
        :param precision: the length of a duration in seconds (default: 5)
        :return: True of False depending on whether the signature is valid for the current (+/- 1) time slot
        """
        # determine time slots (we allow for some variation before and after)
        ref = int(time.time() / precision)
        slots = [ref - 1, ref, ref + 1]

        # generate the token for each time slot and check if for one the signature is valid.
        for slot in slots:
            # logger.info("verify_authorisation_token\tH(url)={}".format(hash_json_object(url).hex()))
            token = hash_string_object(url).hex()

            if body:
                # logger.info("verify_authorisation_token\tH(body)={}".format(hash_json_object(body).hex()))
                token += hash_json_object(body).hex()

            # logger.info("verify_authorisation_token\tH(bytes(slot))={}".format(hash_bytes_object(bytes(slot)).hex()))
            token += hash_bytes_object(bytes(slot)).hex()

            # logger.info("verify_authorisation_token\tH(self.public_as_string())={}".format(
            #     hash_string_object(self.public_as_string()).hex()))
            token += hash_string_object(self.public_as_string()).hex()

            token = hash_string_object(token)
            # logger.info("verify_authorisation_token\ttoken={}".format(token.hex()))

            if self.verify(token, signature):
                return True

        # no valid signature for any of the eligible timeslots
        return False
