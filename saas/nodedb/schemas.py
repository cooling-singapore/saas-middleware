from typing import List, Optional

from pydantic import BaseModel

from saascore.keystore.schemas import Identity as IdentitySchema


class NodeInfo(BaseModel):
    iid: str
    identity: IdentitySchema
    dor_service: bool
    rti_service: bool
    p2p_service_address: str
    rest_service_address: Optional[str]


class NetworkInfo(BaseModel):
    iid: str
    last_seen: int
    p2p_address: str
    rest_address: Optional[str]
    dor_service: bool
    rti_service: bool


class SerialisedIdentity(BaseModel):
    iid: str
    name: str
    email: str
    s_public_key: str
    e_public_key: str
    nonce: int
    signature: str


class ProvenanceInfo(BaseModel):
    content_nodes: List[dict]
    proc_nodes: List[dict]
    steps: List[dict]
