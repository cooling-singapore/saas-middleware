import os
import logging
import json
from threading import Lock

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.rsakeypair import RSAKeyPair

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('Keystore.Keystore')


class Identity:
    specification = {
        'type': 'object',
        'properties': {
            'public_key': {'type': 'string'},
            'name': {'type': 'string'},
            'email': {'type': 'string'},
            'nonce': {'type': 'number'},
            's_public_key': {'type': 'string'},
            'e_public_key': {'type': 'string'}
        },
        'required': ['public_key', 'name', 'email', 'nonce', 's_public_key', 'e_public_key']
    }

    @classmethod
    def create_new(cls, name, email):
        return Identity(RSAKeyPair.create_new(), name, email, 1, ECKeyPair.create_new(), RSAKeyPair.create_new())

    @classmethod
    def deserialise(cls, serialised_identity):
        return Identity(RSAKeyPair.from_public_key_string(serialised_identity['public_key']),
                        serialised_identity['name'], serialised_identity['email'], serialised_identity['nonce'],
                        ECKeyPair.from_public_key_string(serialised_identity['s_public_key']),
                        RSAKeyPair.from_public_key_string(serialised_identity['e_public_key']))

    def __init__(self, public_key, name, email, nonce, s_public_key, e_public_key):
        self._public_key = public_key
        self._name = name
        self._email = email
        self._nonce = nonce
        self._s_public_key = s_public_key
        self._e_public_key = e_public_key

    def serialise(self):
        return {
            'public_key': self._public_key.public_as_string(),
            'name': self._name,
            'email': self._email,
            'nonce': self._nonce,
            's_public_key': self._s_public_key.public_as_string(),
            'e_public_key': self._e_public_key.public_as_string()
        }

    def id(self):
        return self._public_key.iid

    def public_key(self):
        return self._public_key

    def name(self):
        return self._name

    def email(self):
        return self._email

    def nonce(self):
        return self._nonce

    def signing_public_key(self):
        return self._s_public_key

    def encryption_public_key(self):
        return self._e_public_key

    def sign(self, signing_key):
        record = f"{self._public_key.public_as_string()}:{self._name}:{self._email}:{self._nonce}:" \
                 f"{self._s_public_key.public_as_string()}:{self._e_public_key.public_as_string()}"
        signature = signing_key.sign(record.encode('utf-8'))
        return signature

    def verify(self, signature):
        record = f"{self._public_key.public_as_string()}:{self._name}:{self._email}:{self._nonce}:" \
                 f"{self._s_public_key.public_as_string()}:{self._e_public_key.public_as_string()}"
        return self._public_key.verify(record.encode('utf-8'), signature)


class Keystore:
    def __init__(self, path, master, content):
        self._mutex = Lock()
        self._path = path
        self._master = master
        self._public_master = RSAKeyPair.from_public_key(master.public_key)
        self._content = content
        self._s_key = ECKeyPair.from_private_key_string(self._content['identity']['s-key'])
        self._e_key = RSAKeyPair.from_private_key_string(self._content['identity']['e-key'])

        self._sync_to_disk()
        self._refresh_identity()

    @classmethod
    def create(cls, path, name, email, password):
        # create new identity keys: master-key for keystore protection, s-key for signatures, and e-key for encryption
        master = RSAKeyPair.create_new()
        s_key = ECKeyPair.create_new()
        e_key = RSAKeyPair.create_new()

        # write private master key to file
        master.write_private(os.path.join(path, f"{master.iid}.master"), password)

        # create keystore and sync to disk
        keystore_path = os.path.join(path, f"{master.iid}.keystore")
        keystore = Keystore(keystore_path, master, {
            'identity': {
                'name': name,
                'email': email,
                'nonce': 1,
                's-key': s_key.private_as_string(),
                'e-key': e_key.private_as_string()
            },
            'object_keys': {}
        })

        logger.info(f"keystore created: id={keystore.identity().id()} "
                    f"s_key={keystore._s_key.public_as_string()} "
                    f"e_key={keystore._e_key.public_as_string()}")

        return keystore

    @classmethod
    def load(cls, path, keystore_id, password):
        try:
            # load master key
            master_path = os.path.join(path, f"{keystore_id}.master")
            master = RSAKeyPair.from_private_key_file(master_path, password)

            # load keystore contents
            keystore_path = os.path.join(path, f"{keystore_id}.keystore")
            with open(keystore_path, 'rb') as f:
                content_enc = f.read()
                content_enc = master.decrypt(content_enc).decode('utf-8')
                content = json.loads(content_enc)

            # create keystore
            keystore = Keystore(keystore_path, master, content)

            logger.info(f"keystore loaded: id={keystore.identity().id()} "
                        f"s_key={keystore._s_key.public_as_string()} "
                        f"e_key={keystore._e_key.public_as_string()}")

            return keystore

        except ValueError as e:
            logger.error(f"keystore could not be loaded. reason: {e}")
            return None

    @classmethod
    def delete(cls, path, keystore_id):
        if Keystore.is_valid(path, keystore_id):
            os.remove(os.path.join(path, f"{keystore_id}.master"))
            os.remove(os.path.join(path, f"{keystore_id}.keystore"))
            return True

        else:
            return False

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

    def update(self, s_key=None, e_key=None, name=None, email=None):
        with self._mutex:
            is_dirty = False

            if s_key is not None and self._content['identity']['s-key'] != s_key.private_as_string():
                self._content['identity']['s-key'] = s_key.private_as_string()
                self._s_key = s_key
                is_dirty = True

            if e_key is not None and self._content['identity']['e-key'] != e_key.private_as_string():
                self._content['identity']['e-key'] = e_key.private_as_string()
                self._e_key = e_key
                is_dirty = True

            if name is not None and self._content['identity']['name'] != name:
                self._content['identity']['name'] = name
                is_dirty = True

            if email is not None and self._content['identity']['email'] != email:
                self._content['identity']['email'] = email
                is_dirty = True

            # has there been an actual change of information?
            if is_dirty:
                self._content['identity']['nonce'] += 1
                self._sync_to_disk()
                self._refresh_identity()

            return self._identity.sign(self._master)

    def identity(self):
        return self._identity

    def signing_key(self):
        return self._s_key

    def encryption_key(self):
        return self._e_key

    def object_keys(self):
        with self._mutex:
            return list(self._content['object_keys'].keys())

    def add_object_key(self, object_id, key):
        with self._mutex:
            self._content['object_keys'][object_id] = key.decode('utf-8')
            self._sync_to_disk()

    def get_object_key(self, object_id):
        with self._mutex:
            return self._content['object_keys'][object_id].encode('utf-8') \
                if object_id in self._content['object_keys'] else None

    def _sync_to_disk(self):
        content_enc = json.dumps(self._content)
        content_enc = self._master.encrypt(content_enc.encode('utf-8'))
        with open(self._path, 'wb') as f:
            f.write(content_enc)

    def _refresh_identity(self):
        public_key = RSAKeyPair.from_public_key(self._master.public_key)
        s_public_key = ECKeyPair.from_public_key(self._s_key.public_key)
        e_public_key = RSAKeyPair.from_public_key(self._e_key.public_key)
        self._identity = Identity(public_key,
                                  self._content['identity']['name'],
                                  self._content['identity']['email'],
                                  self._content['identity']['nonce'],
                                  s_public_key, e_public_key)
