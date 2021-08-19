from __future__ import annotations

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.keypair import KeyPair
from saas.cryptography.rsakeypair import RSAKeyPair


class Identity:
    def __init__(self, iid: str, name: str, email: str,
                 s_public_key: KeyPair, e_public_key: KeyPair, nonce: int,
                 signature: str = None) -> None:
        self._id = iid
        self._name = name
        self._email = email
        self._s_public_key = s_public_key
        self._e_public_key = e_public_key
        self._nonce = nonce
        self._signature = signature

    @classmethod
    def deserialise(self, content: dict) -> Identity:
        s_public_key = ECKeyPair.from_public_key_string(content['s_public_key'])
        e_public_key = RSAKeyPair.from_public_key_string(content['e_public_key'])
        return Identity(content['iid'], content['name'], content['email'], s_public_key, e_public_key,
                        content['nonce'], content['signature'])

    @property
    def id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def email(self) -> str:
        return self._email

    @property
    def nonce(self) -> int:
        return self._nonce

    @property
    def signature(self) -> str:
        return self._signature

    def s_public_key_as_string(self) -> str:
        return self._s_public_key.public_as_string()

    def e_public_key_as_string(self) -> str:
        return self._e_public_key.public_as_string()

    def verify(self, message: bytes, signature: str) -> bool:
        return self._s_public_key.verify(message, signature)

    def encrypt(self, content: bytes) -> bytes:
        return self._e_public_key.encrypt(content, base64_encoded=True)

    def authenticate(self, s_key: KeyPair) -> str:
        token = f"{self._id}:{self._name}:{self._email}:{self._nonce}:" \
                f"{self._s_public_key.public_as_string()}:" \
                f"{self._e_public_key.public_as_string()}"

        self._signature = s_key.sign(token.encode('utf-8'))
        return self._signature

    def is_authentic(self) -> bool:
        token = f"{self._id}:{self._name}:{self._email}:{self._nonce}:" \
                f"{self._s_public_key.public_as_string()}:" \
                f"{self._e_public_key.public_as_string()}"

        return self._s_public_key.verify(token.encode('utf-8'), self._signature)

    def serialise(self) -> dict:
        return {
            'iid': self._id,
            'name': self._name,
            'email': self._email,
            's_public_key': self._s_public_key.public_as_string(),
            'e_public_key': self._e_public_key.public_as_string(),
            'nonce': self._nonce,
            'signature': self._signature
        }
