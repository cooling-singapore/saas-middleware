from typing import Optional, Sequence, Any

from pydantic import BaseModel


class EndpointDefinition(BaseModel):
    method: str
    prefix: str
    rule: str
    function: Any
    response_model: Any
    dependencies: Optional[Sequence[Any]]
