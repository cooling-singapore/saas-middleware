from typing import List, Dict, Union

from pydantic import BaseModel, validator

from saas.keystore.asset import Asset
from saas.keystore.assets.keypair import KeyPairAsset
from saas.keystore.exceptions import KeystoreException

REQUIRED_ASSETS = ["master-key", "signing-key", "encryption-key"]


class BaseKeystore(BaseModel):
    class KeystoreProfile(BaseModel):
        name: str
        email: str
        notes: str

    iid: str
    profile: KeystoreProfile
    assets: list
    nonce: int


class KeystoreObject(BaseKeystore):
    assets: Dict[str, Union[Asset, KeyPairAsset]]

    class Config:
        arbitrary_types_allowed = True

    @validator('assets')
    def contains_required_key_assets(cls, v):
        """Keystore must contain keys of certain types"""
        for key in REQUIRED_ASSETS:
            if key not in v:
                raise KeystoreException(f"Required asset '{key}' not found in keystore content.")
            return v


class SerializedKeystore(BaseKeystore):
    class KeystoreAsset(BaseModel):
        type: str
        key: str
        content: dict

    assets: List[KeystoreAsset]
    signature: str

    @validator('assets')
    def contains_required_key_assets(cls, v):
        """Keystore must contain keys of certain types"""
        asset_keys = set([asset.key for asset in v])
        for key in REQUIRED_ASSETS:
            if key not in asset_keys:
                raise KeystoreException(f"Required asset '{key}' not found in keystore content.")
            return v


class Identity(BaseModel):
    iid: str
    name: str
    email: str
    s_public_key: str
    e_public_key: str
    nonce: int
    signature: str
