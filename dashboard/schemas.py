from typing import List

from pydantic import BaseModel, Field
from saas.core.exceptions import ExceptionContent
from saas.core.helpers import generate_random_string
from saas.core.logging import Logging

logger = Logging.get('dashboard.schemas')


class DashboardRuntimeError(Exception):
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


class DataObjectProvenance(BaseModel):
    """
    Provenance information is similar to data object recipes. However, provenance shows the entire history - so as far
    as the node is aware of it. This includes a history of all steps necessary to produce the data object of interest.
    Due to the nature of provenance information, the result is a graph structure. Provenance information includes data
    nodes and processor nodes that are put into relation to each other via processing steps. A step uses which processor
    is used and what data objects it consumes and produces. Steps are establishing edges between data and processor
    nodes.

    An individual processing step in the history of a data object. Information includes a reference to the processor
    used by this step as well as references to all input and output data objects consumed and produced by the processor
    during this step. References are used here because the same processor or data object may be used by more than one
    step.
    """
    data_nodes: List[dict] = Field(..., title="Data Nodes", description="A mapping of references to specific content data object information.")
    proc_nodes: List[dict] = Field(..., title="Processor Nodes", description="A mapping of references to specific processor information (GPPs).")
    steps: List[dict] = Field(..., title="Steps", description="A list of all (known) steps needed to produce the data object of interest.")
    missing: List[str] = Field(..., title="Missing Information", description="A list of references for which there is no further information avaialable. This is either due to the fact that not all provenance information is known to the node or because of first order data objects, i.e., data objects that have not been generated but uploaded to the DOR.")
