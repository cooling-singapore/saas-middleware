from typing import Optional

from pydantic import BaseModel, Field

from saas.core.helpers import generate_random_string


class ExceptionContent(BaseModel):
    """
    The content of a SaaS exception.
    """
    id: str = Field(..., title="Id", description="The unique identifier of this exception.")
    reason: str = Field(..., title="Reason", description="The reason that caused this exception.")
    details: Optional[dict] = Field(title="Details", description="Supporting information about this exception.")


class SaaSRuntimeException(Exception):
    def __init__(self, reason: str, details: dict = None):
        self._content = ExceptionContent(id=generate_random_string(16), reason=reason, details=details)

    @property
    def id(self):
        return self._content.id

    @property
    def reason(self):
        return self._content.reason

    @property
    def details(self):
        return self._content.details

    @property
    def content(self) -> ExceptionContent:
        return self._content
