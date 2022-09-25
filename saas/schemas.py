from typing import Union, Literal, List, Optional, Dict

from pydantic import BaseModel, Field


class ObjectTag(BaseModel):
    key: str
    value: str


class TaskInputReference(BaseModel):
    name: str
    type: Literal["reference"]
    obj_id: str
    user_signature: Optional[str]
    c_hash: Optional[str]


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


class ResumeDescriptor(BaseModel):
    job_id: str
    task_descriptor: TaskDescriptor
    paths: Dict[str, str]
    pid: str
    pid_paths: Dict[str, str]
    retain_job: bool


class JobDescriptor(BaseModel):
    id: str
    proc_id: str
    owner_iid: str
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


class JobStatus(BaseModel):
    job_id: str
    task: dict


class ProcessorStatus(BaseModel):
    state: str
    pending: List[dict]
    active: Optional[dict]


class GitProcessorPointer(BaseModel):
    source: str
    commit_id: str
    proc_path: str
    proc_config: str
    proc_descriptor: Optional[ProcessorDescriptor]
