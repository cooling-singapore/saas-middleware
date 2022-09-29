from __future__ import annotations

from pydantic import BaseModel
from typing import Optional

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.rsakeypair import RSAKeyPair


def generate_identity_token(iid: str, name: str, email: str, nonce: int, s_public_key: str, e_public_key: str) -> str:
    return f"{iid}:{name}:{email}:{nonce}:{s_public_key}:{e_public_key}"


class Identity(BaseModel):
    id: str
    name: str
    email: str
    s_public_key: str
    e_public_key: str
    nonce: int
    signature: Optional[str]

    def verify(self, message: bytes, signature: str) -> bool:
        s_key = ECKeyPair.from_public_key_string(self.s_public_key)
        return s_key.verify(message, signature)

    def encrypt(self, content: bytes) -> bytes:
        e_key = RSAKeyPair.from_public_key_string(self.e_public_key)
        return e_key.encrypt(content, base64_encoded=True)

    def verify_integrity(self) -> bool:
        token = generate_identity_token(self.id, self.name, self.email, self.nonce,
                                        self.s_public_key, self.e_public_key)
        return self.verify(token.encode('utf-8'), self.signature)
