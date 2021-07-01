import base64
import logging
import math
import cryptography.hazmat.primitives.serialization as serialization

from saas.cryptography.keypair import KeyPair

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa


logger = logging.getLogger('RSAKeyPair')


class RSAKeyPair(KeyPair):
    """
    RSAKeyPair encapsulates the functionality for RSA key pairs. It provides a number of convenience
    methods to create a RSAKeyPair instance as well as for (de)serialisation of keys. An RSA key pair consists of a
    private key and a public key whereby the public key can be derived from the private key. RSAKeyPair provides also
    a number of methods for creating and verifying signatures and authentication/authorisation tokens.
    """

    def __init__(self, private_key, public_key):
        KeyPair.__init__(self, private_key, public_key)

    @classmethod
    def create_new(cls, key_size=4096):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        return RSAKeyPair.from_private_key(private_key)

    @classmethod
    def from_private_key(cls, private_key):
        public_key = private_key.public_key()
        return RSAKeyPair(private_key, public_key)

    @classmethod
    def from_private_key_string(cls, private_key_string, password=None):
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
        return RSAKeyPair(private_key, public_key)

    @classmethod
    def from_private_key_file(cls, path, password):
        with open(path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                data=f.read(),
                password=password.encode('utf-8'),
                backend=default_backend()
            )
            return RSAKeyPair.from_private_key(private_key)

    @classmethod
    def from_public_key(cls, public_key):
        return RSAKeyPair(None, public_key)

    @classmethod
    def from_public_key_bytes(cls, public_key_bytes):
        public_key = serialization.load_pem_public_key(
            data=public_key_bytes,
            backend=default_backend()
        )
        return RSAKeyPair.from_public_key(public_key)

    @classmethod
    def from_public_key_string(cls, public_key_string):
        if '-----BEGIN PUBLIC KEY-----' not in public_key_string:
            public_key_string = '\n'.join(public_key_string[i:i + 64] for i in range(0, len(public_key_string), 64))
            public_key_string = f"-----BEGIN PUBLIC KEY-----\n{public_key_string}\n-----END PUBLIC KEY-----"

        return RSAKeyPair.from_public_key_bytes(public_key_string.encode('utf-8'))

    @classmethod
    def from_public_key_file(cls, path):
        with open(path, "rb") as f:
            public_key = serialization.load_pem_public_key(
                data=f.read(),
                backend=default_backend()
            )
            return RSAKeyPair.from_public_key(public_key)

    def sign(self, message):
        """
        Sign a message using the private key.
        :param message: the message that has to be signed
        :return: the signature
        """
        return self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        ).hex()

    def verify(self, message, signature):
        """
        Verifies the signature for a given message using the public key.
        :param message: the message that has been used for signing
        :param signature: the signature
        :return: True of False depending on whether the signature is valid
        """
        try:
            self.public_key.verify(bytes.fromhex(signature),
                                   message,
                                   padding.PSS(
                                       mgf=padding.MGF1(hashes.SHA256()),
                                       salt_length=padding.PSS.MAX_LENGTH
                                   ),
                                   hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    def encrypt(self, message, base64_encoded=False):
        """
        Encrypts a message using the public key.
        :param base64_encoded:
        :param message: the unencrypted message
        :return: encrypted message
        """
        chunk_size = int(self.public_key.key_size / 16)
        n_chunks = math.ceil(len(message) / chunk_size)
        result = bytearray()
        for i in range(n_chunks):
            chunk = self.public_key.encrypt(
                message[i*chunk_size:(i+1)*chunk_size],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            result += bytearray(chunk)

        if base64_encoded:
            return base64.b64encode(bytes(result))
        else:
            return bytes(result)

    def decrypt(self, message, base64_encoded=False):
        """
        Decrypts a message using the private key.
        :param base64_encoded:
        :param message: the encrypted message
        :return: unencrypted message
        """
        message = base64.b64decode(message) if base64_encoded else message

        chunk_size = int(self.public_key.key_size / 8)
        n_chunks = int(len(message) / chunk_size)
        result = bytearray()
        for i in range(n_chunks):
            chunk = self.private_key.decrypt(
                message[i*chunk_size:(i+1)*chunk_size],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            result += bytearray(chunk)

        return bytes(result)
