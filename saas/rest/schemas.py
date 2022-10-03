from dataclasses import dataclass
from typing import Any, Optional, Sequence


@dataclass
class EndpointDefinition:
    method: str
    prefix: str
    rule: str
    function: Any
    response_model: Any
    dependencies: Optional[Sequence[Any]]
