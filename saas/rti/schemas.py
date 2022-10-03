from typing import Literal, Optional, List, Union, Dict

from pydantic import BaseModel

from saas.dor.schemas import GitProcessorPointer


class Task(BaseModel):
    class InputReference(BaseModel):
        name: str
        type: Literal["reference"]
        obj_id: str
        user_signature: Optional[str]
        c_hash: Optional[str]

    class InputValue(BaseModel):
        name: str
        type: Literal["value"]
        value: dict

    class Output(BaseModel):
        name: str
        owner_iid: str
        restricted_access: bool
        content_encrypted: bool
        target_node_iid: Optional[str]

    proc_id: str
    user_iid: str
    input: List[Union[InputReference, InputValue]]
    output: List[Output]


class Job(BaseModel):
    id: str
    task: Task
    retain: bool


class ResumableJob(Job):
    paths: Dict[str, str]
    pid: str
    pid_paths: Dict[str, str]


class JobStatus(BaseModel):
    state: str
    status: dict
    job: Union[Job, ResumableJob]


class Processor(BaseModel):
    proc_id: str
    gpp: GitProcessorPointer


class ProcessorStatus(BaseModel):
    state: str
    pending: List[JobStatus]
    active: Optional[JobStatus]
