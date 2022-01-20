from __future__ import annotations

from copy import copy
from typing import TypeVar, Generic

from saas.keystore.asset import Asset, deserialise, serialise

import saas.cryptography.keypair as keypair
import saas.helpers as helpers


class Credentials:
    def __init__(self, record: dict):
        self._record = record

    @property
    def record(self):
        return self._record


class GithubCredentials(Credentials):
    def __init__(self, login: str, personal_access_token: str):
        super().__init__({
            'login': login,
            'personal_access_token': personal_access_token
        })

    @classmethod
    def from_record(cls, record: dict) -> GithubCredentials:
        return GithubCredentials(record['login'], record['personal_access_token'])

    @property
    def login(self):
        return self._record['login']

    @property
    def personal_access_token(self):
        return self._record['personal_access_token']


class SSHCredentials(Credentials):
    def __init__(self, host: str, login: str, key: str, key_is_password: bool) -> None:
        super().__init__({
            'host': host,
            'login': login,
            'key': key,
            'key_is_password': key_is_password
        })

    @classmethod
    def from_record(cls, record: dict) -> SSHCredentials:
        return SSHCredentials(record['host'], record['login'], record['key'],
                              str(record['key_is_password']).lower() == 'true')

    @property
    def host(self) -> str:
        return self._record['host']

    @property
    def login(self) -> str:
        return self._record['login']

    @property
    def key(self) -> str:
        return self._record['key']

    @property
    def key_is_password(self) -> bool:
        return self._record['key_is_password']


T = TypeVar('T')


class CredentialsAsset(Generic[T], Asset):
    content_schema = {
        'type': 'object',
        'properties': {
            'type': {'type': 'string'},
            'credentials': {'type': 'string'}
        },
        'required': ['credentials']
    }

    def __init__(self, key: str, credentials: dict[str, T], ctype: type) -> None:
        super().__init__(key)

        self._credentials = credentials
        self._ctype = ctype

    @classmethod
    def create(cls, key: str, ctype: type) -> T:
        return CredentialsAsset[T](key, {}, ctype)

    @classmethod
    def deserialise(cls, key: str, content: dict[str, T], master_key: keypair.KeyPair) -> T:
        # verify content
        helpers.validate_json(content, CredentialsAsset.content_schema)

        # deserialise content
        credentials = deserialise(content, ['credentials'], master_key)['credentials']

        # create credential items using the correct type
        ctype = globals()[content['ctype']]
        for k, v in credentials.items():
            credentials[k] = ctype.from_record(v)

        return CredentialsAsset[T](key, credentials, ctype)

    def serialise(self, protect_with: keypair.KeyPair) -> dict:
        credentials = copy(self._credentials)
        for k, v in credentials.items():
            credentials[k] = v.record

        return {
            'type': type(self).__name__,
            'key': self._key,
            'content': serialise({
                'ctype': self._ctype.__name__,
                'credentials': credentials,
            }, protect_with=protect_with, protected_properties=['credentials'])
        }

    def index(self) -> list[str]:
        return list(self._credentials.keys())

    def update(self, name: str, item: T) -> None:
        self._credentials[name] = item

    def get(self, name: str) -> T:
        return self._credentials.get(name)

    def remove(self, name: str) -> None:
        if name in self._credentials:
            self._credentials.pop(name)

    def size(self) -> int:
        return len(self._credentials)
