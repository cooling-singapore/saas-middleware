import logging
import cryptography.hazmat.primitives.serialization as serialization

from saas.cryptography.hashing import hash_bytes_object

logger = logging.getLogger('KeyPair')


class KeyPair:
    """
    KeyPair encapsulates the functionality for asymmetric key pairs. It provides a number of convenience methods for
    (de)serialisation of keys. A key pair consists of a private key and a public key whereby the public key can be
    derived from the private key.
    """

    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
        self.iid = hash_bytes_object(self.public_as_bytes()).hex()
        self.short_iid = f"{self.iid[:4]}...{self.iid[-4:]}"

    def private_as_bytes(self, password=None):
        """
        Serialises the private key and returns it as byte array (or None in case this KeyPair instance does not
        have a private key).
        :param password: the password to protect the private key
        :return: byte array representing the password-protected private key or None if no private key is available
        """
        key_encryption_algorithm = serialization.NoEncryption()
        if password:
            key_encryption_algorithm = serialization.BestAvailableEncryption(password.encode('utf-8'))

        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=key_encryption_algorithm
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

    def private_as_string(self, password=None, truncate=True):
        """
        Serialises the private key and returns it as string (or None in case this KeyPair instance does not
        have a private key).
        :param password: the password to protect the private key
        :param truncate: indicates whether or not to create a truncated string (default: False)
        :return: string representing of the private key or None if no private key is available
        """
        if self.private_key:
            result = self.private_as_bytes(password).decode('utf-8')
            if truncate:
                if password:
                    result = result.replace('\n', '')
                    result = result[37:-35]
                else:
                    result = result.replace('\n', '')
                    result = result[27:-25]

            return result
        else:
            return None

    def public_as_string(self, truncate=True):
        """
        Serialises the public key and returns it as string. If truncate=True, the PEM prefix and suffix is removed
        as well as all white space characters.
        :param truncate: indicates whether or not to create a truncated string (default: True)
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
