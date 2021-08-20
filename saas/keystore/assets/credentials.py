from __future__ import annotations

from copy import copy
from typing import TypeVar, Generic

from saas.cryptography.keypair import KeyPair
from saas.helpers import validate_json
from saas.keystore.asset import Asset, deserialise, serialise


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
    def __init__(self, host: str, login: str, key_path: str):
        super().__init__({
            'host': host,
            'login': login,
            'key_path': key_path
        })

    @classmethod
    def from_record(cls, record: dict) -> SSHCredentials:
        return SSHCredentials(record['host'], record['login'], record['key_path'])

    @property
    def host(self):
        return self._record['host']

    @property
    def login(self):
        return self._record['login']

    @property
    def key_path(self):
        return self._record['key_path']


class SMTPCredentials(Credentials):
    def __init__(self, server: str, login: str, password: str):
        super().__init__({
            'server': server,
            'login': login,
            'password': password
        })

    @classmethod
    def from_record(cls, record: dict) -> SMTPCredentials:
        return SMTPCredentials(record['server'], record['login'], record['password'])

    @property
    def server(self):
        return self._record['server']

    @property
    def login(self):
        return self._record['login']

    @property
    def password(self):
        return self._record['password']


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
    def deserialise(cls, key: str, content: dict[str, T], master_key: KeyPair) -> T:
        # verify content
        validate_json(content, CredentialsAsset.content_schema)

        # deserialise content
        credentials = deserialise(content, ['credentials'], master_key)['credentials']

        # create credential items using the correct type
        ctype = globals()[content['ctype']]
        for k, v in credentials.items():
            credentials[k] = ctype.from_record(v)

        return CredentialsAsset[T](key, credentials, ctype)

    def serialise(self, protect_with: KeyPair):
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

    def update(self, name: str, item: T) -> None:
        self._credentials[name] = item

    def get(self, name: str) -> T:
        return self._credentials.get(name)
