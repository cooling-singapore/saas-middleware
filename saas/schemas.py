from enum import unique, Enum
from typing import Union, Literal, List, Optional

from pydantic import BaseModel


@unique
class InputObjectTypes(str, Enum):
    reference = "reference"
    value = "value"


class TaskDescriptor(BaseModel):

    class TaskInputReference(BaseModel):
        name: str
        type: Literal["reference"]
        obj_id: str
        user_signature: Optional[str]

    class TaskInputValue(BaseModel):
        name: str
        type: Literal["value"]
        value: dict

    class TaskOutput(BaseModel):
        name: str
        owner_iid: str
        restricted_access: bool
        content_encrypted: bool
        target_node_iid: Optional[str]

    processor_id: str
    input: List[Union[TaskInputReference, TaskInputValue]]
    output: List[TaskOutput]
    user_iid: str


class JobDescriptor(BaseModel):
    id: str
    proc_id: str
    task: TaskDescriptor


class ProcessorDescriptor(BaseModel):
    # TODO: Add schema property
    class ProcessorDataObject(BaseModel):
        name: str
        data_type: str
        data_format: str

    name: str
    input: List[ProcessorDataObject]
    output: List[ProcessorDataObject]
    configurations: List[str]


class GitProcessorPointer(BaseModel):
    source: str
    commit_id: str
    proc_path: str
    proc_config: str
    proc_descriptor: Optional[ProcessorDescriptor]


class NetworkNode(BaseModel):
    iid: str
    last_seen: int
    p2p_address: str
    rest_address: Optional[str]
    dor_service: bool
    rti_service: bool


class ObjectRecipe(BaseModel):
    class RecipeProduct(BaseModel):
        name: str
        c_hash: str
        data_type: str
        data_format: str

    class RecipeProcessor(BaseModel):
        proc_id: str
        gpp: GitProcessorPointer

    class RecipeInputReference(BaseModel):
        name: str
        data_type: str
        data_format: str
        type: Literal["reference"]
        c_hash: str

    class RecipeInputValue(BaseModel):
        name: str
        data_type: str
        data_format: str
        type: Literal["value"]
        value: dict

    product: RecipeProduct
    processor: RecipeProcessor
    input: List[Union[RecipeInputReference, RecipeInputValue]]


class ObjectProvenance(BaseModel):
    class ProvenanceContentNode(BaseModel):
        c_hash: str
        type: Literal['original', 'derived']
        data_type: str
        data_format: str

    class ProvenanceProcNode(BaseModel):
        gpp_hash: str
        gpp: GitProcessorPointer

    class ProvenanceSteps(BaseModel):
        consume: List[str]
        processor: Optional[str]
        produce: Optional[str]

    content_nodes: Optional[List[ProvenanceContentNode]]
    proc_nodes: Optional[List[ProvenanceProcNode]]
    steps: Optional[List[ProvenanceSteps]]

