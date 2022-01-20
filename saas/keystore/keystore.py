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
from saas.helpers import generate_random_string, write_json_to_file
from saas.keystore.asset import Asset
from saas.keystore.assets.contentkeys import ContentKeysAsset
from saas.keystore.assets.credentials import CredentialsAsset
from saas.keystore.assets.keypair import KeyPairAsset, MasterKeyPairAsset
from saas.keystore.exceptions import KeystoreException
from saas.keystore.identity import Identity
from saas.keystore.schemas import SerializedKeystore, KeystoreObject
from saas.logging import Logging

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
        # update and authenticate identity
        self._identity = Identity(id=self._keystore.iid,
                                  name=self._keystore.profile.name,
                                  email=self._keystore.profile.email,
                                  s_public_key=ECKeyPair.from_public_key(self._s_key.public_key),
                                  e_public_key=RSAKeyPair.from_public_key(self._e_key.public_key),
                                  nonce=self._keystore.nonce)
        self._identity.authenticate(self._s_key)

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
