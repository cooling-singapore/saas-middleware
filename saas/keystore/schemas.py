from typing import Dict, Any

from pydantic import BaseModel


class KeystoreProfile(BaseModel):
    name: str
    email: str


class KeystoreContent(BaseModel):
    iid: str
    profile: KeystoreProfile
    nonce: int
    signature: str
    assets: Dict[str, Any]


class GithubCredentials(BaseModel):
    login: str
    personal_access_token: str


class SSHCredentials(BaseModel):
    host: str
    login: str
    key: str
    key_is_password: bool
