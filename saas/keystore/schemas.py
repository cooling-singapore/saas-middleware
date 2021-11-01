from typing import List

from pydantic import BaseModel


class Keystore(BaseModel):
    class KeystoreProfile(BaseModel):
        name: str
        email: str
        notes: str

    class KeystoreAsset(BaseModel):
        type: str
        key: str
        content: dict

    iid: str
    profile: KeystoreProfile
    assets: List[KeystoreAsset]
    nonce: int
    signature: str


class Identity(BaseModel):
    iid: str
    name: str
    email: str
    s_public_key: str
    e_public_key: str
    nonce: int
    signature: str
