from typing import Tuple, Optional

from pydantic import BaseModel

from saas.keystore.identity import Identity


class NodeInfo(BaseModel):
    identity: Identity
    last_seen: int
    dor_service: bool
    rti_service: bool
    p2p_address: Tuple[str, int]
    rest_address: Optional[Tuple[str, int]]
