from dataclasses import dataclass
from typing import Any, Optional, Sequence, Tuple

from pydantic import BaseModel


@dataclass
class EndpointDefinition:
    method: str
    prefix: Tuple[str, str]
    rule: str
    function: Any
    response_model: Any
    dependencies: Optional[Sequence[Any]]


class Token(BaseModel):
    access_token: str
    token_type: str
    expiry: int
