from typing import Union, Literal, List, Optional

from pydantic import BaseModel, Field


class ObjectTag(BaseModel):
    key: str
    value: str


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


# TODO: Update schema once pydantic supports discriminator
class TaskDescriptor(BaseModel):
    processor_id: str
    input: List[Union[TaskInputReference, TaskInputValue]]
    output: List[TaskOutput]
    user_iid: str


class JobDescriptor(BaseModel):
    id: str
    proc_id: str
    task: TaskDescriptor
    retain: bool


class ProcessorDescriptor(BaseModel):
    # TODO: Add schema property
    class ProcessorDataObject(BaseModel):
        name: str
        data_type: str
        data_format: str
        data_schema: Optional[dict] = Field(alias="schema")

    name: str
    input: List[ProcessorDataObject]
    output: List[ProcessorDataObject]
    configurations: List[str]


class ProcessorStatus(BaseModel):
    state: str
    active: Optional[dict]
    pending: List[dict]


class GitProcessorPointer(BaseModel):
    source: str
    commit_id: str
    proc_path: str
    proc_config: str
    proc_descriptor: Optional[ProcessorDescriptor]


# class NetworkNode(BaseModel):
#     iid: str
#     last_seen: int
#     p2p_address: str
#     rest_address: Optional[str]
#     dor_service: bool
#     rti_service: bool
