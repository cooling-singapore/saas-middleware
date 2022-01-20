from __future__ import annotations

from saas.cryptography.keypair import KeyPair
from saas.helpers import validate_json
from saas.keystore.asset import Asset, deserialise, serialise


class ContentKeysAsset(Asset):
    content_schema = {
        'type': 'object',
        'properties': {
            'keys': {'type': 'string'}
        },
        'required': ['keys']
    }

    def __init__(self, key: str, content_keys: dict = None) -> None:
        super().__init__(key)

        self._content_keys = content_keys if content_keys else {}

    @classmethod
    def deserialise(cls, key: str, content: dict, master_key: KeyPair) -> ContentKeysAsset:
        # verify content
        validate_json(content, ContentKeysAsset.content_schema)

        # deserialise content
        content_keys = deserialise(content, ['keys'], master_key)['keys']

        return ContentKeysAsset(key, content_keys)

    def serialise(self, protect_with: KeyPair) -> dict:
        return {
            'type': type(self).__name__,
            'key': self._key,
            'content': serialise({
                'keys': self._content_keys,
            }, protect_with=protect_with, protected_properties=['keys'])
        }

    def update(self, obj_id: str, content_key: str) -> None:
        self._content_keys[obj_id] = content_key

    def get(self, obj_id: str) -> str:
        return self._content_keys.get(obj_id)
