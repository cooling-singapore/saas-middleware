import logging
import time
import cryptography.hazmat.primitives.serialization as serialization

from saas.cryptography.hashing import hash_json_object, hash_string_object, hash_bytes_object

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

    def sign(self, message):
        pass

    def verify(self, message, signature):
        pass

    def encrypt(self, message, base64_encoded=False):
        pass

    def decrypt(self, message, base64_encoded=False):
        pass

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

