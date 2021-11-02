from __future__ import annotations

import os
import string
from threading import Lock
from typing import Any, Dict
from pydantic import BaseModel, validator

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.helpers import hash_json_object
from saas.cryptography.keypair import KeyPair
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.helpers import generate_random_string, write_json_to_file, read_json_from_file, validate_json
from saas.keystore.asset import Asset
from saas.keystore.assets.contentkeys import ContentKeysAsset
from saas.keystore.assets.credentials import CredentialsAsset
from saas.keystore.assets.keypair import KeyPairAsset, MasterKeyPairAsset
from saas.keystore.exceptions import KeystoreException
from saas.keystore.identity import Identity
from saas.keystore.schemas import Keystore as KeystoreSchema
from saas.logging import Logging

logger = Logging.get('keystore.Keystore')


# class Keystore:
#     def __init__(self, path: str, password: str, iid: str, assets: dict, profile: dict = None, nonce: int = 0) -> None:
#         self._mutex = Lock()
#         self._path = path
#         self._password = password
#
#         self._iid = iid
#         self._profile = profile if profile else {
#             'name': '',
#             'email': '',
#             'notes': ''
#         }
#         self.nonce = nonce
#         self._assets = assets
#
#         # create shortcuts
#         self._master = self._assets['master-key'].get()
#         self._s_key = self._assets['signing-key'].get()
#         self._e_key = self._assets['encryption-key'].get()
#
#         # update identity
#         self._update_identity()

REQUIRED_ASSETS = ["master-key", "signing-key", "encryption-key"]


class Keystore(BaseModel):
    class KeystoreProfile(BaseModel):
        name: str = ""
        email: str = ""
        notes: str = ""

    iid: str
    profile: KeystoreProfile = KeystoreProfile()
    assets: Dict[str, Asset]
    nonce: int = 0

    _path: str
    _password: str
    _identity: Identity
    _mutex: Lock

    # required key assets references
    _master: KeyPair
    _s_key: KeyPair
    _e_key: KeyPair

    @validator('assets')
    def contains_required_key_assets(cls, v):
        for key in REQUIRED_ASSETS:
            if key not in v:
                raise KeystoreException(f"Required asset '{key}' not found in keystore content.")
            return v

    class Config:
        underscore_attrs_are_private = True
        # arbitrary_types_allowed = True

    def __init__(self, path: str, password: str, **data) -> None:
        super().__init__(**data)

        self._path = os.path.join(path, f"{self.iid}.json")
        self._password = password
        self._mutex = Lock()

        self._master = self.assets['master-key'].get()
        self._s_key = self.assets['signing-key'].get()
        self._e_key = self.assets['encryption-key'].get()

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
        keystore = Keystore(keystore_path, password, iid=keystore_id, assets=assets)

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
        content = read_json_from_file(keystore_path)
        if not validate_json(content, KeystoreSchema.schema()):
            raise KeystoreException("Keystore content not compliant with json schema.")

        # create dict of assets
        assets = {}
        for serialised_asset in content['assets']:
            assets[serialised_asset['key']] = serialised_asset

        # check if mandatory signing and encryption key assets are present
        required = ['master-key', 'signing-key', 'encryption-key', 'content-keys']
        for key in required:
            if key not in assets:
                raise KeystoreException(f"Required asset '{key}' not found in keystore content.")

        # deserialise the master key and make shortcut
        assets['master-key'] = MasterKeyPairAsset.from_content(
            'master-key', assets['master-key']['content'], password
        )
        master = assets['master-key'].get()

        # deserialise all other assets
        for key, serialised_asset in assets.items():
            if key != 'master-key':
                if serialised_asset['type'] == KeyPairAsset.__name__:
                    assets[key] = KeyPairAsset.from_content(key, serialised_asset['content'], master)

                elif serialised_asset['type'] == ContentKeysAsset.__name__:
                    assets[key] = ContentKeysAsset.from_content(key, serialised_asset['content'], master)

                elif serialised_asset['type'] == ContentKeysAsset.__name__:
                    assets[key] = ContentKeysAsset.from_content(key, serialised_asset['content'], master)

                elif serialised_asset['type'] == CredentialsAsset.__name__:
                    assets[key] = CredentialsAsset.deserialise(key, serialised_asset['content'], master)

        # check if signature is valid
        s_key = assets['signing-key'].get()
        content_hash = hash_json_object(content, exclusions=['signature'])
        if not s_key.verify(content_hash, content['signature']):
            raise KeystoreException(f"Invalid keystore content signature: "
                                    f"content_hash={content_hash}, signature={content['signature']}.")

        # create keystore
        keystore = Keystore(keystore_path, password, iid=keystore_id, assets=assets,
                            profile=content['profile'], nonce=content['nonce'])
        logger.info(f"keystore loaded: iid={keystore.identity.id} "
                    f"s_key={keystore._s_key.public_as_string()} "
                    f"e_key={keystore._e_key.public_as_string()}")

        return keystore

    @property
    def identity(self) -> Identity:
        with self._mutex:
            return self._identity

    def update_profile(self, name: str = None, email: str = None) -> Identity:
        with self._mutex:
            if name is not None:
                self.profile.name = name

            if email is not None:
                self.profile.name = email

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

    def encryption_key(self) -> KeyPair:
        with self._mutex:
            return self._e_key

    def signing_key(self) -> KeyPair:
        with self._mutex:
            return self._s_key

    def has_asset(self, key: str) -> bool:
        with self._mutex:
            return key in self.assets

    def get_asset(self, key: str) -> Any:
        with self._mutex:
            return self.assets.get(key)

    def update_asset(self, asset: Asset) -> None:
        with self._mutex:
            self.assets[asset.key] = asset
            self._sync_to_disk()

    def _update_identity(self) -> None:
        # update and authenticate identity
        self._identity = Identity(self.iid,
                                  self.profile.name,
                                  self.profile.email,
                                  ECKeyPair.from_public_key(self._s_key.public_key),
                                  RSAKeyPair.from_public_key(self._e_key.public_key),
                                  self.nonce)
        self._identity.authenticate(self._s_key)

    def _sync_to_disk(self) -> None:
        # increase the nonce
        self.nonce += 1

        # serialise all assets
        serialised_assets = []
        for key, asset in self.assets.items():
            if key == 'master-key':
                serialised_assets.append(asset.serialise(password=self._password))
            else:
                serialised_assets.append(asset.serialise(protect_with=self._master))

        # bootstrap the content
        content = {
            'iid': self.iid,
            'profile': self.profile.dict(),
            'assets': serialised_assets,
            'nonce': self.nonce
        }

        # generate signature
        content['signature'] = self._s_key.sign(hash_json_object(content))

        # write contents to disk
        write_json_to_file(content, self._path, schema=KeystoreSchema.schema())

        # update identity
        self._update_identity()
