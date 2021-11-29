from __future__ import annotations

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.keypair import KeyPair
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.helpers import validate_json
from saas.keystore.asset import Asset, deserialise, serialise
from saas.keystore.exceptions import KeystoreException


class KeyPairAsset(Asset):
    content_schema = {
        'type': 'object',
        'properties': {
            'info': {'type': 'string'},
            'private_key': {'type': 'string'}
        },
        'required': ['info', 'private_key']
    }

    def __init__(self, key: str, keypair: KeyPair) -> None:
        super().__init__(key)

        self._keypair = keypair

    @classmethod
    def deserialise(cls, key: str, content: dict, master_key: KeyPair) -> KeyPairAsset:
        # verify content
        validate_json(content, KeyPairAsset.content_schema)

        # deserialise content
        content = deserialise(content, ['private_key'], master_key)

        # create keypair from content
        if content['info'].startswith('RSA'):
            keypair = RSAKeyPair.from_private_key_string(content['private_key'])
            return KeyPairAsset(key, keypair)

        elif content['info'].startswith('EC'):
            keypair = ECKeyPair.from_private_key_string(content['private_key'])
            return KeyPairAsset(key, keypair)

        else:
            raise KeystoreException(f"Unrecognised keypair type '{content['info']}'")

    def serialise(self, protect_with: KeyPair) -> dict:
        return {
            'type': type(self).__name__,
            'key': self._key,
            'content':  serialise({
                'info': self._keypair.info(),
                'private_key': self._keypair.private_as_string()
            }, protect_with=protect_with, protected_properties=['private_key'])
        }

    def get(self) -> KeyPair:
        return self._keypair


class MasterKeyPairAsset(Asset):
    content_schema = {
        'type': 'object',
        'properties': {
            'info': {'type': 'string'},
            'pppk': {'type': 'string'}
        },
        'required': ['info', 'pppk']
    }

    def __init__(self, key: str, keypair: KeyPair) -> None:
        super().__init__(key)

        self._keypair = keypair

    @classmethod
    def deserialise(cls, key: str, content: dict, password: str) -> MasterKeyPairAsset:
        # verify content
        validate_json(content, MasterKeyPairAsset.content_schema)

        # create keypair from content
        if content['info'].startswith('RSA'):
            keypair = RSAKeyPair.from_private_key_string(content['pppk'], password=password)
            return MasterKeyPairAsset(key, keypair)

        elif content['info'].startswith('EC'):
            keypair = ECKeyPair.from_private_key_string(content['pppk'], password=password)
            return MasterKeyPairAsset(key, keypair)

        else:
            raise KeystoreException(f"Unrecognised keypair type '{content['info']}'")

    def serialise(self, protect_with: str) -> dict:
        return {
            'type': type(self).__name__,
            'key': self._key,
            'content':  {
                'info': self._keypair.info(),
                'pppk': self._keypair.private_as_string(password=protect_with)
            }
        }

    def get(self) -> KeyPair:
        return self._keypair

