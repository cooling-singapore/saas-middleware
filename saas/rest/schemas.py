from dataclasses import dataclass
from typing import Optional, Sequence, Any


@dataclass
class EndpointDefinition:
    method: str
    prefix: str
    rule: str
    function: Any
    response_model: Any
    dependencies: Optional[Sequence[Any]]
