import logging
import time
import cryptography.hazmat.primitives.serialization as serialization

from saas.cryptography.keypair import KeyPair
from saas.cryptography.hashing import hash_file_content, hash_json_object, hash_string_object, hash_bytes_object

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


logger = logging.getLogger('ECKeyPair')


class ECKeyPair(KeyPair):
    """
    ECKeyPair encapsulates the functionality for Elliptic Curve (EC) key pairs. It provides a number of convenience
    methods to create a ECKeyPair instance as well as for (de)serialisation of keys. A EC key pair consists of a
    private key and a public key whereby the public key can be derived from the private key. ECKeyPair provides also
    a number of methods for creating and verifying signatures and authentication/authorisation tokens.
    """

    def __init__(self, private_key, public_key):
        KeyPair.__init__(self, private_key, public_key)

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
    def from_private_key_string(cls, private_key_string, password=None):
        """
        Creates an ECKeyPair instance based on a given private key string.
        :param private_key_string:
        :param password: the password used to protect the private key
        :return: ECKeyPair instance
        """
        if password:
            password = password.encode('utf-8')

            if '-----BEGIN ENCRYPTED PRIVATE KEY-----' not in private_key_string:
                private_key_string = '\n'.join(private_key_string[i:i + 64] for i in range(0, len(private_key_string), 64))
                private_key_string = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{private_key_string}\n-----END ENCRYPTED PRIVATE KEY-----"

        else:
            if '-----BEGIN PRIVATE KEY-----' not in private_key_string:
                private_key_string = '\n'.join(private_key_string[i:i + 64] for i in range(0, len(private_key_string), 64))
                private_key_string = f"-----BEGIN PRIVATE KEY-----\n{private_key_string}\n-----END PRIVATE KEY-----"

        private_key = serialization.load_pem_private_key(
            data=private_key_string.encode('utf-8'),
            password=password,
            backend=default_backend()
        )
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
