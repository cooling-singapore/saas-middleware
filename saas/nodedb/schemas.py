from typing import Tuple, Optional

from pydantic import BaseModel, Field

from saas.core.identity import Identity


class NodeInfo(BaseModel):
    """
    Information about a SaaS node in the network.
    """
    identity: Identity = Field(..., title="Node Identity", description="The identity of the node.")
    last_seen: int = Field(..., title="Last Seen", description="The timestamp (in UTC milliseconds since the beginning of the epoch) when the node was seen last.", example=1664849510076)
    dor_service: bool = Field(..., title="DOR Service", description="Indicates if the node provides a DOR service.", example=True)
    rti_service: bool = Field(..., title="RTI Service", description="Indicates if the node provides a RTI service.", example=True)
    p2p_address: Tuple[str, int] = Field(..., title="P2P Address", description="The address of the P2P service.", example=('127.0.0.1', 4001))
    rest_address: Optional[Tuple[str, int]] = Field(title="REST Address", description="The address of the REST service (if applicable - not all nodes have the REST interface enabled).", example=('127.0.0.1', 5001))
