from __future__ import annotations

import os
import string

from threading import Lock
from typing import Any, Dict
from pydantic import BaseModel, ValidationError

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.helpers import hash_json_object
from saas.cryptography.keypair import KeyPair
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.dor.schemas import GithubCredentials, SSHCredentials
from saas.helpers import generate_random_string, write_json_to_file, read_json_from_file, validate_json
from saas.keystore.assets import MasterKeyPairAsset, KeyPairAsset, ContentKeysAsset, SSHCredentialsAsset, \
    GithubCredentialsAsset
from saas.keystore.exceptions import KeystoreException, KeystoreCredentialsException
from saas.keystore.identity import generate_identity_token, Identity
from saas.log import Logging

logger = Logging.get('keystore.Keystore')


class KeystoreProfile(BaseModel):
    name: str
    email: str


class KeystoreContent(BaseModel):
    iid: str
    profile: KeystoreProfile
    nonce: int
    signature: str
    assets: Dict[str, Any]


class Keystore:
    def __init__(self, path: str, password: str, content: KeystoreContent) -> None:
        self._mutex = Lock()
        self._path = path
        self._password = password
        self._content = content

        self._loaded = {
            'master-key': MasterKeyPairAsset.load(content.assets['master-key'], password)
        }
        self._identity = None

        self._master = self._loaded['master-key'].get()

        # load all other assets
        for key, asset in content.assets.items():
            if key != 'master-key':
                if asset['type'] == KeyPairAsset.__name__:
                    self._loaded[key] = KeyPairAsset.load(asset, self._master)

                elif asset['type'] == ContentKeysAsset.__name__:
                    self._loaded[key] = ContentKeysAsset.load(asset, self._master)

                elif asset['type'] == GithubCredentialsAsset.__name__:
                    self._loaded[key] = GithubCredentialsAsset.load(asset, self._master)

                elif asset['type'] == SSHCredentialsAsset.__name__:
                    self._loaded[key] = SSHCredentialsAsset.load(asset, self._master)

        # keep references to essential keys
        self._s_key = self._loaded['signing-key'].get()
        self._e_key = self._loaded['encryption-key'].get()

        # check if signature is valid
        content_hash = hash_json_object(content.dict(), exclusions=['signature'])
        if not self._s_key.verify(content_hash, content.signature):
            raise KeystoreException(f"Invalid keystore content signature: "
                                    f"content_hash={content_hash}, signature={content.signature}.")

        self._update_identity()

    @classmethod
    def create(cls, path: str, name: str, email: str, password: str) -> Keystore:
        # create random keystore id
        iid = generate_random_string(64, characters=string.ascii_lowercase+string.digits)

        # create required assets
        master_key = MasterKeyPairAsset(RSAKeyPair.create_new())
        signing_key = KeyPairAsset(ECKeyPair.create_new())
        encryption_key = KeyPairAsset(RSAKeyPair.create_new())
        content_keys = ContentKeysAsset()
        ssh_credentials = SSHCredentialsAsset()
        github_credentials = GithubCredentialsAsset()

        # create the keystore content
        content = {
            'iid': iid,
            'profile': {
                'name': name,
                'email': email
            },
            'nonce': 0,
            'assets': {
                'master-key': master_key.store(password),
                'signing-key': signing_key.store(master_key.get()),
                'encryption-key': encryption_key.store(master_key.get()),
                'content-keys': content_keys.store(master_key.get()),
                'ssh-credentials': ssh_credentials.store(master_key.get()),
                'github-credentials': github_credentials.store(master_key.get())
            }
        }

        # sign the contents of the keystore
        content_hash = hash_json_object(content)
        content['signature'] = signing_key.get().sign(content_hash)

        # create keystore
        keystore_path = os.path.join(path, f"{iid}.json")
        keystore = Keystore(keystore_path, password, KeystoreContent.parse_obj(content))
        keystore.sync()

        logger.info(f"keystore created: id={keystore.identity.id} "
                    f"s_key={keystore._s_key.public_as_string()} "
                    f"e_key={keystore._e_key.public_as_string()}")

        return keystore

    @classmethod
    def load(cls, keystore_path: str, password: str) -> Keystore:
        # check if keystore file exists
        if not os.path.isfile(keystore_path):
            raise FileNotFoundError(f"Keystore content not found at {keystore_path}")

        # load content and validate
        try:
            content = KeystoreContent.parse_file(keystore_path)
        except ValidationError:
            raise KeystoreException("Keystore content not compliant with json schema.")

        # check if we have required assets
        for required in ['master-key', 'signing-key', 'encryption-key', 'content-keys', 'ssh-credentials',
                         'github-credentials']:
            if required not in content.assets:
                raise KeystoreException(f"Keystore invalid: {required} found.")

        # create keystore
        keystore = Keystore(keystore_path, password, content)
        logger.info(f"keystore loaded: iid={keystore.identity.id} "
                    f"s_key={keystore._s_key.public_as_string()} "
                    f"e_key={keystore._e_key.public_as_string()}")

        return keystore

    @property
    def identity(self) -> Identity:
        with self._mutex:
            return self._identity

    @property
    def encryption_key(self) -> KeyPair:
        with self._mutex:
            return self._e_key

    @property
    def signing_key(self) -> KeyPair:
        with self._mutex:
            return self._s_key

    def update_profile(self, name: str = None, email: str = None) -> Identity:
        with self._mutex:
            if name is not None:
                self._content.profile.name = name

            if email is not None:
                self._content.profile.email = email

        if name or email:
            self.sync()

        return self._identity

    def encrypt(self, content: bytes) -> bytes:
        with self._mutex:
            return self._e_key.encrypt(content, base64_encoded=True)

    def decrypt(self, content: bytes) -> bytes:
        with self._mutex:
            return self._e_key.decrypt(content, base64_encoded=True)

    def sign(self, message: bytes) -> str:
        with self._mutex:
            return self._s_key.sign(message)

    def verify(self, message: bytes, signature: str) -> bool:
        with self._mutex:
            return self._s_key.verify(message, signature)

    @property
    def content_keys(self) -> ContentKeysAsset:
        with self._mutex:
            return self._loaded['content-keys']

    @property
    def ssh_credentials(self) -> SSHCredentialsAsset:
        with self._mutex:
            return self._loaded['ssh-credentials']

    @property
    def github_credentials(self) -> GithubCredentialsAsset:
        with self._mutex:
            return self._loaded['github-credentials']

    def _update_identity(self) -> None:
        # generate valid signature for the identity
        token = generate_identity_token(iid=self._content.iid,
                                        name=self._content.profile.name,
                                        email=self._content.profile.email,
                                        s_public_key=self._s_key.public_as_string(),
                                        e_public_key=self._e_key.public_as_string(),
                                        nonce=self._content.nonce)
        signature = self._s_key.sign(token.encode('utf-8'))

        # update the signature
        self._identity = Identity(id=self._content.iid,
                                  name=self._content.profile.name,
                                  email=self._content.profile.email,
                                  s_public_key=self._s_key.public_as_string(),
                                  e_public_key=self._e_key.public_as_string(),
                                  nonce=self._content.nonce,
                                  signature=signature)

        # verify the identity's integrity
        if not self._identity.verify_integrity():
            raise KeystoreException(f"Keystore produced invalid identity", details={
                'identity': self._identity
            })

    def sync(self) -> None:
        with self._mutex:
            # increase the nonce
            self._content.nonce += 1

            # serialise all assets
            self._content.assets = {
                key: asset.store(protection=self._password if key == 'master-key' else self._master)
                for key, asset in self._loaded.items()
            }

            # sign the contents of the keystore
            content_hash = hash_json_object(self._content.dict(), exclusions=['signature'])
            self._content.signature = self._s_key.sign(content_hash)

            # write contents to disk
            write_json_to_file(self._content.dict(), self._path)

            # update identity
            self._update_identity()


def update_keystore_from_credentials(keystore: Keystore, credentials_path: str = None) -> None:
    """
    Updates a keystore with credentials loaded from credentials file. This is a convenience function useful for
    testing purposes. A valid example content may look something like this:
    {
        "name": "John Doe",
        "email": "john.doe@internet.com",
        "ssh-credentials": [
            {
            "name": "my-remote-machine-A",
            "login": "johnd",
            "host": "10.8.0.1",
            "password": "super-secure-password-123"
            },
            {
            "name": "my-remote-machine-B",
            "login": "johnd",
            "host": "10.8.0.2",
            "key_path": "/home/johndoe/machine-b-key"
            }
        ],
        "github-credentials": [
            {
                "repository": "https://github.com/my-repo",
                "login": "JohnDoe",
                "personal_access_token": "ghp_xyz..."
            }
        ]
    }

    For SSH credentials note that you can either indicate a password or a path to a key file.

    :param keystore: the keystore that is to be updated
    :param credentials_path: the optional path to the credentials file (default is $HOME/.saas-credentials.json)
    :return:
    """

    credentials_schema = {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'email': {'type': 'string'},
            'ssh-credentials': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'name': {'type': 'string'},
                        'login': {'type': 'string'},
                        'host': {'type': 'string'},
                        'password': {'type': 'string'},
                        'key_path': {'type': 'string'}
                    },
                    'required': ['name', 'login', 'host']
                }
            },
            'github-credentials': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'repository': {'type': 'string'},
                        'login': {'type': 'string'},
                        'personal_access_token': {'type': 'string'}
                    },
                    'required': ['repository', 'login', 'personal_access_token']
                }
            }
        }
    }

    # load the credentials and validate
    path = credentials_path if credentials_path else os.path.join(os.environ['HOME'], '.saas-credentials.json')
    credentials = read_json_from_file(path)
    if not validate_json(content=credentials, schema=credentials_schema):
        raise KeystoreCredentialsException(path, credentials, credentials_schema)

    # update profile (if applicable)
    keystore.update_profile(name=credentials['name'] if 'name' in credentials else None,
                            email=credentials['email'] if 'email' in credentials else None)

    # do we have SSH credentials?
    if 'ssh-credentials' in credentials:
        for item in credentials['ssh-credentials']:
            # password or key path?
            if 'password' in item:
                keystore.ssh_credentials.update(item['name'],
                                                SSHCredentials(host=item['host'], login=item['login'],
                                                               key=item['password'], key_is_password=True))

            elif 'key_path' in item:
                # read the ssh key from file
                with open(item['key_path'], 'r') as f:
                    ssh_key = f.read()

                keystore.ssh_credentials.update(item['name'],
                                                SSHCredentials(host=item['host'], login=item['login'],
                                                               key=ssh_key, key_is_password=False))

            else:
                raise RuntimeError(f"Unexpected SSH credentials format: {item}")

        keystore.sync()

    # do we have Github credentials?
    if 'github-credentials' in credentials:
        for item in credentials['github-credentials']:
            keystore.github_credentials.update(item['repository'], GithubCredentials.parse_obj(item))
        keystore.sync()
