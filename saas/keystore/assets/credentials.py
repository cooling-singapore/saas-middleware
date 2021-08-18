from __future__ import annotations

from saas.cryptography.keypair import KeyPair
from saas.helpers import validate_json
from saas.keystore.asset import Asset, deserialise, serialise


class CredentialsAsset(Asset):
    content_schema = {
        'type': 'object',
        'properties': {
            'credentials': {'type': 'string'}
        },
        'required': ['credentials']
    }

    def __init__(self, key: str, credentials: dict) -> None:
        super().__init__(key)

        self._credentials = credentials

    def serialise(self, protect_with: KeyPair):
        return {
            'type': type(self).__name__,
            'key': self._key,
            'content': serialise({
                'credentials': self._credentials,
            }, protect_with=protect_with, protected_properties=['credentials'])
        }

    def get(self, name: str) -> dict:
        return self._credentials.get(name)


class GithubCredentialsAsset(CredentialsAsset):
    @classmethod
    def create(cls, key: str) -> GithubCredentialsAsset:
        return GithubCredentialsAsset(key, {})

    @classmethod
    def from_content(cls, key: str, content: dict, master_key: KeyPair) -> GithubCredentialsAsset:
        # verify content
        validate_json(content, CredentialsAsset.content_schema)

        # deserialise content
        credentials = deserialise(content, ['credentials'], master_key)['credentials']

        return GithubCredentialsAsset(key, credentials)

    def update(self, repository: str, login: str, personal_access_token: str):
        self._credentials[repository] = {
            'login': login,
            'personal_access_token': personal_access_token
        }


class SSHCredentialsAsset(CredentialsAsset):
    @classmethod
    def create(cls, key: str) -> SSHCredentialsAsset:
        return SSHCredentialsAsset(key, {})

    @classmethod
    def from_content(cls, key: str, content: dict, master_key: KeyPair) -> SSHCredentialsAsset:
        # verify content
        validate_json(content, CredentialsAsset.content_schema)

        # deserialise content
        credentials = deserialise(content, ['credentials'], master_key)['credentials']

        return SSHCredentialsAsset(key, credentials)

    def update(self, name: str, host: str, login: str, password: str = None, key_path: str = None):
        self._credentials[name] = {
            'host': host,
            'login': login
        }

        if password:
            self._credentials[name]['password'] = password

        if key_path:
            self._credentials[name]['key_path'] = key_path


class SMTPCredentialsAsset(CredentialsAsset):
    @classmethod
    def create(cls, key: str) -> SMTPCredentialsAsset:
        return SMTPCredentialsAsset(key, {})

    @classmethod
    def from_content(cls, key: str, content: dict, master_key: KeyPair) -> SMTPCredentialsAsset:
        # verify content
        validate_json(content, CredentialsAsset.content_schema)

        # deserialise content
        credentials = deserialise(content, ['credentials'], master_key)['credentials']

        return SMTPCredentialsAsset(key, credentials)

    def update(self, email: str, server: str, login: str, password: str):
        self._credentials[email] = {
            'server': server,
            'login': login,
            'password': password
        }
