from enum import Enum
from typing import Literal, Optional, List, Union, Dict

from pydantic import BaseModel

from saas.dor.schemas import GitProcessorPointer
from saas.exceptions import ExceptionContent


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


class ReconnectInfo(BaseModel):
    paths: Dict[str, str]
    pid: str
    pid_paths: Dict[str, str]


class JobStatus(BaseModel):
    class State(str, Enum):
        INITIALISED = 'initialised'
        RUNNING = 'running'
        FAILED = 'failed'
        TIMEOUT = 'timeout'
        SUCCESSFUL = 'successful'

    class Error(BaseModel):
        message: str
        exception: ExceptionContent

    state: Literal[State.INITIALISED, State.RUNNING, State.FAILED, State.TIMEOUT, State.SUCCESSFUL]
    progress: int
    output: Dict[str, str]
    notes: dict
    job: Job
    reconnect: Optional[ReconnectInfo]
    errors: Optional[List[Error]]


class Processor(BaseModel):
    proc_id: str
    gpp: GitProcessorPointer


class ProcessorStatus(BaseModel):
    state: str
    pending: List[Job]
    active: Optional[Job]
