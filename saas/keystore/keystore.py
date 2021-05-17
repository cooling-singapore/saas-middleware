import os
import logging
import json

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.rsakeypair import RSAKeyPair

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('Keystore.Keystore')


def sign_identity_record(key, name, email, nonce):
    record = f"{key.iid}:{name}:{email}:{nonce}"
    signature = key.sign(record.encode('utf-8'))
    return record, signature


def verify_identity_record(key, name, email, nonce, signature):
    record = f"{key.iid}:{name}:{email}:{nonce}"
    return key.verify(record.encode('utf-8'), signature)


class Keystore:
    def __init__(self, path, master, content):
        self.path = path
        self.master = master
        self.content = content
        self.identity = ECKeyPair.from_private_key_string(self.content['identity']['key'])

    @classmethod
    def create(cls, path, name, email, password):
        # create new identity key pair
        identity = ECKeyPair.create_new()
        logger.info(f"keystore identity created: id={identity.iid} public_key={identity.public_as_string()}")

        # create new master key and write to file
        master = RSAKeyPair.create_new()
        master.write_private(os.path.join(path, f"{identity.iid}.master"), password)
        logger.info(f"keystore master key created: id={master.iid} public_key={master.public_as_string()}")

        # write content
        content = {
            'identity': {
                'name': name,
                'email': email,
                'nonce': 1,
                'key': identity.private_as_string()
            },
            'object_keys': {}
        }

        # create keystore
        keystore_path = os.path.join(path, f"{identity.iid}.keystore")
        keystore = Keystore(keystore_path, master, content)
        keystore.sync_to_disk()

        return keystore

    @classmethod
    def load(cls, path, keystore_id, password):
        # load master key
        master_path = os.path.join(path, f"{keystore_id}.master")
        master = RSAKeyPair.from_private_key_file(master_path, password)
        logger.info(f"keystore master key loaded: id={master.iid} public_key={master.public_as_string()}")

        # load keystore contents
        keystore_path = os.path.join(path, f"{keystore_id}.keystore")
        with open(keystore_path, 'rb') as f:
            content_enc = f.read()
            content_enc = master.decrypt(content_enc).decode('utf-8')
            content = json.loads(content_enc)

        return Keystore(keystore_path, master, content)

    @classmethod
    def is_valid(cls, path, keystore_id):
        # has the id the correct length?
        if len(keystore_id) != 64:
            return False

        # do the corresponding files exist?
        master_path = os.path.join(path, f"{keystore_id}.master")
        keystore_path = os.path.join(path, f"{keystore_id}.keystore")
        if not os.path.isfile(master_path) or not os.path.isfile(keystore_path):
            return False

        # is the master file a PEM file containing an encrypted private key?
        s0 = '-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
        s1 = '-----END ENCRYPTED PRIVATE KEY-----\n'
        with open(master_path, 'r') as f:
            lines = f.readlines()
            if lines[0] != s0 or lines[-1] != s1:
                return False

        return True

    def sync_to_disk(self):
        content_enc = json.dumps(self.content)
        content_enc = self.master.encrypt(content_enc.encode('utf-8'))
        with open(self.path, 'wb') as f:
            f.write(content_enc)

    def update(self, name=None, email=None):
        self.content['identity']['nonce'] += 1

        if name:
            self.content['identity']['name'] = name

        if email:
            self.content['identity']['email'] = email

        self.sync_to_disk()

        return sign_identity_record(self.identity, self.name(), self.email(), self.nonce())

    def id(self, truncate=False):
        return self.identity.short_iid if truncate else self.identity.iid

    def name(self):
        return self.content['identity']['name']

    def email(self):
        return self.content['identity']['email']

    def nonce(self):
        return self.content['identity']['nonce']

    def add_object_key(self, object_id, key):
        self.content['object_keys'][object_id] = key.decode('utf-8')
        self.sync_to_disk()

    def get_object_key(self, object_id):
        if object_id not in self.content['object_keys']:
            return None

        else:
            return self.content['object_keys'][object_id].encode('utf-8')
