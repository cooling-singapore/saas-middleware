from __future__ import annotations

from dataclasses import dataclass

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.keypair import KeyPair
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.keystore.schemas import Identity as IdentitySchema


@dataclass
class Identity:
    id: str
    name: str
    email: str
    s_public_key: KeyPair
    e_public_key: KeyPair
    nonce: int
    signature: str = None

    @property
    def short_id(self) -> str:
        return self.id[:8]

    @classmethod
    def deserialise(cls, content: dict) -> Identity:
        # Validate Identity
        _identity = IdentitySchema.parse_obj(content)

        s_public_key = ECKeyPair.from_public_key_string(content['s_public_key'])
        e_public_key = RSAKeyPair.from_public_key_string(content['e_public_key'])
        return cls(id=_identity.iid, name=_identity.name, email=_identity.email, nonce=_identity.nonce,
                   signature=_identity.signature, s_public_key=s_public_key, e_public_key=e_public_key)

    def s_public_key_as_string(self) -> str:
        return self.s_public_key.public_as_string()

    def e_public_key_as_string(self) -> str:
        return self.e_public_key.public_as_string()

    def verify(self, message: bytes, signature: str) -> bool:
        return self.s_public_key.verify(message, signature)

    def encrypt(self, content: bytes) -> bytes:
        return self.e_public_key.encrypt(content, base64_encoded=True)

    def _generate_token(self) -> str:
        return f"{self.id}:{self.name}:{self.email}:{self.nonce}:" \
               f"{self.s_public_key.public_as_string()}:" \
               f"{self.e_public_key.public_as_string()}"

    def authenticate(self, s_key: KeyPair) -> str:
        self.signature = s_key.sign(self._generate_token().encode('utf-8'))
        return self.signature

    def is_authentic(self) -> bool:
        return self.s_public_key.verify(self._generate_token().encode('utf-8'), self.signature)

    def serialise(self) -> dict:
        content = {
            'iid': self.id,
            'name': self.name,
            'email': self.email,
            's_public_key': self.s_public_key.public_as_string(),
            'e_public_key': self.e_public_key.public_as_string(),
            'nonce': self.nonce,
            'signature': self.signature
        }

        return content
