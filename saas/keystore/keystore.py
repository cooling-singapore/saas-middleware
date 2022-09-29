from __future__ import annotations

import os
import string
from threading import Lock
from typing import Any

import pydantic

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.helpers import hash_json_object
from saas.cryptography.keypair import KeyPair
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.helpers import generate_random_string, write_json_to_file, read_json_from_file, validate_json
from saas.keystore.asset import Asset
from saas.keystore.assets.contentkeys import ContentKeysAsset
from saas.keystore.assets.credentials import CredentialsAsset, SSHCredentials, GithubCredentials
from saas.keystore.assets.keypair import MasterKeyPairAsset, KeyPairAsset
from saas.keystore.exceptions import KeystoreException, KeystoreCredentialsException
from saas.keystore.identity import Identity, generate_identity_token
from saas.keystore.schemas import KeystoreObject, SerializedKeystore
from saas.log import Logging

logger = Logging.get('keystore.Keystore')


class Keystore:
    def __init__(self, path: str, password: str, keystore_object: KeystoreObject) -> None:
        self._path = path
        self._password = password
        self._mutex = Lock()

        self._keystore = keystore_object

        # Keep references to essential keys
        self._master = self._keystore.assets['master-key'].get()
        self._s_key = self._keystore.assets['signing-key'].get()
        self._e_key = self._keystore.assets['encryption-key'].get()

        self._update_identity()

    @classmethod
    def create(cls, path: str, name: str, email: str, password: str) -> Keystore:
        # create random keystore id
        keystore_id = generate_random_string(64, characters=string.ascii_lowercase+string.digits)

        # create required assets
        assets = {
            'master-key': MasterKeyPairAsset('master-key', RSAKeyPair.create_new()),
            'signing-key': KeyPairAsset('signing-key', ECKeyPair.create_new()),
            'encryption-key': KeyPairAsset('encryption-key', RSAKeyPair.create_new()),
            'content-keys': ContentKeysAsset('content-keys')
        }

        # create keystore
        keystore_path = os.path.join(path, f"{keystore_id}.json")
        keystore = cls(keystore_path, password,
                       KeystoreObject(iid=keystore_id, assets=assets, nonce=0,
                                      profile=KeystoreObject.KeystoreProfile(name="", email="", notes="")))

        # update profile (which will also sync it to disk for the first time)
        keystore.update_profile(name=name, email=email)

        logger.info(f"keystore created: iid={keystore.identity.id} "
                    f"s_key={keystore._s_key.public_as_string()} "
                    f"e_key={keystore._e_key.public_as_string()}")

        return keystore

    @classmethod
    def load(cls, path: str, keystore_id: str, password: str) -> Keystore:
        # check if keystore file exists
        keystore_path = os.path.join(path, f"{keystore_id}.json")
        if not os.path.isfile(keystore_path):
            raise FileNotFoundError(f"Keystore content not found at {keystore_path}")

        # load content and validate
        try:
            content = SerializedKeystore.parse_file(keystore_path)
        except pydantic.ValidationError:
            raise KeystoreException("Keystore content not compliant with json schema.")

        # create dict of assets
        assets = {serialised_asset.key: serialised_asset for serialised_asset in content.assets}

        # deserialise the master key and make shortcut
        assets['master-key'] = MasterKeyPairAsset.deserialise(
            'master-key', assets['master-key'].content, password
        )
        master = assets['master-key'].get()

        # deserialise all other assets
        for key, serialised_asset in assets.items():
            if key != 'master-key':
                if serialised_asset.type == KeyPairAsset.__name__:
                    assets[key] = KeyPairAsset.deserialise(key, serialised_asset.content, master)

                elif serialised_asset.type == ContentKeysAsset.__name__:
                    assets[key] = ContentKeysAsset.deserialise(key, serialised_asset.content, master)

                elif serialised_asset.type == CredentialsAsset.__name__:
                    assets[key] = CredentialsAsset.deserialise(key, serialised_asset.content, master)

        # check if signature is valid
        s_key = assets['signing-key'].get()
        content_hash = hash_json_object(content.dict(), exclusions=['signature'])
        content_signature = content.signature
        if not s_key.verify(content_hash, content_signature):
            raise KeystoreException(f"Invalid keystore content signature: "
                                    f"content_hash={content_hash}, signature={content_signature}.")

        # create keystore
        keystore = cls(keystore_path, password,
                       KeystoreObject(iid=keystore_id, assets=assets, profile=content.profile, nonce=content.nonce))
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
                self._keystore.profile.name = name

            if email is not None:
                self._keystore.profile.email = email

            if name or email:
                self._sync_to_disk()

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

    def has_asset(self, key: str) -> bool:
        with self._mutex:
            return key in self._keystore.assets

    def get_asset(self, key: str) -> Any:
        with self._mutex:
            return self._keystore.assets.get(key)

    def update_asset(self, asset: Asset) -> None:
        with self._mutex:
            self._keystore.assets[asset.key] = asset
            self._sync_to_disk()

    def _update_identity(self) -> None:
        iid = self._keystore.iid
        name = self._keystore.profile.name
        email = self._keystore.profile.email
        s_public_key = self._s_key.public_as_string()
        e_public_key = self._e_key.public_as_string()
        nonce = self._keystore.nonce

        # generate valid signature for the identity
        token = generate_identity_token(iid, name, email, nonce, s_public_key, e_public_key)
        signature = self._s_key.sign(token.encode('utf-8'))

        # update the signature
        self._identity = Identity.parse_obj({
            'id': iid,
            'name': name,
            'email': email,
            's_public_key': s_public_key,
            'e_public_key': e_public_key,
            'nonce': nonce,
            'signature': signature
        })

        # verify the identity's integrity
        if not self._identity.verify_integrity():
            raise KeystoreException(f"Keystore produced invalid identity", details={
                'identity': self._identity
            })

    def _sync_to_disk(self) -> None:
        # increase the nonce
        self._keystore.nonce += 1

        # serialise all assets
        serialised_assets = []
        for key, asset in self._keystore.assets.items():
            protection = self._password if key == 'master-key' else self._master
            serialised_assets.append(asset.serialise(protect_with=protection))

        # bootstrap the content
        content = self._keystore.dict(exclude={"assets"})
        content["assets"] = serialised_assets
        # generate signature
        content['signature'] = self._s_key.sign(hash_json_object(content))

        # write contents to disk
        write_json_to_file(content, self._path, schema=SerializedKeystore.schema())

        # update identity
        self._update_identity()


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
        ssh_cred = CredentialsAsset[SSHCredentials].create('ssh-credentials', SSHCredentials)
        for item in credentials['ssh-credentials']:
            # password or key path?
            if 'password' in item:
                ssh_cred.update(item['name'], SSHCredentials(
                    item['host'],
                    item['login'],
                    item['password'],
                    True
                ))
            elif 'key_path' in item:
                # read the ssh key from file
                with open(item['key_path'], 'r') as f:
                    ssh_key = f.read()
                ssh_cred.update(item['name'], SSHCredentials(
                    item['host'],
                    item['login'],
                    ssh_key,
                    False
                ))
            else:
                raise RuntimeError(f"Unexpected SSH credentials format: {item}")

        keystore.update_asset(ssh_cred)

    # do we have Github credentials?
    if 'github-credentials' in credentials:
        github_cred = CredentialsAsset[GithubCredentials].create('github-credentials', GithubCredentials)
        for item in credentials['github-credentials']:
            github_cred.update(item['repository'], GithubCredentials(
                item['login'],
                item['personal_access_token']
            ))
        keystore.update_asset(github_cred)
