from enum import Enum
from typing import Literal, Optional, List, Union, Dict

from pydantic import BaseModel, Field

from saas.core.exceptions import ExceptionContent
from saas.dor.schemas import GitProcessorPointer, CDataObject


class Task(BaseModel):
    """
    Information about a task. This includes a processor, and details about the input and output consumed and produced
    as part of this task.
    """
    class InputReference(BaseModel):
        name: str = Field(..., title="Name", description="The name of the input (needs to exactly match the input as defined by the processor).")
        type: Literal["reference"] = Field(..., title="Type", description="Must be 'reference' for by-reference inputs.", example="reference")
        obj_id: str = Field(..., title="Object Id", description="The id of the object to be used for this input.")
        user_signature: Optional[str] = Field(title="User Signature", description="A valid signature by the identity who owns the task. The RTI will use this signature to verify the user has access to the data object. User signature is only relevant and needed in case the referenced data object has restricted access.")
        c_hash: Optional[str] = Field(title="Content Hash", description="The content hash of this input.")

    class InputValue(BaseModel):
        name: str = Field(..., title="Name", description="The name of the input (needs to exactly match the input as defined by the processor).")
        type: Literal["value"] = Field(..., title="Type", description="Must be 'value' for by-value inputs.", example="value")
        value: dict = Field(..., title="Value", description="The actual content or value of this input. This can be a JSON object.")

    class Output(BaseModel):
        name: str = Field(..., title="Name", description="The name of the output (needs to exactly match the output as defined by the processor).")
        owner_iid: str = Field(..., title="", description="The id of the identity who will be the owner of this output data object once it has been created as part of this task.")
        restricted_access: bool = Field(..., title="Access Restricted", description="Indicates if access to the data object content should be restricted.", example=False)
        content_encrypted: bool = Field(..., title="Content Encrypted", description="Indicates if the content of this data object should be encrypted using the owner's public encryption key.", example=False)
        target_node_iid: Optional[str] = Field(title="", description="", example="")

    proc_id: str = Field(..., title="Processor Id", description="The id of the processor to be used for this task.")
    user_iid: str = Field(..., title="User IId", description="The id of the user's identity who owns this task.")
    input: List[Union[InputReference, InputValue]] = Field(..., title="Input", description="Information needed for every input defined by the processor.")
    output: List[Output] = Field(..., title="Output", description="Information needed for every output defined by the processor.")


class Job(BaseModel):
    """
    Information about a job.
    """
    id: str = Field(..., title="Id", description="The job id.", example="Ikn7dPv6")
    task: Task = Field(..., title="Task", description="The task of this job")
    retain: bool = Field(..., title="Retain", description="Indicates if the RTI should retain the working directory of this job. This is only used for debugging and testing purposes.", example=False)


class ReconnectInfo(BaseModel):
    """
    Necessary information how an RTI can reconnect to a job that is executed by a remotely-deployed processor.
    """
    paths: Dict[str, str] = Field(..., title="Paths", description="A mapping of paths used by the job.")
    pid: str = Field(..., title="PID", description="The process id of the job as assigned by the operating system.", example=3453)
    pid_paths: Dict[str, str] = Field(..., title="PID Paths", description="A mapping of paths used by the process that executes the job.")


class JobStatus(BaseModel):
    """
    Status information about a job.
    """
    class State(str, Enum):
        """
        The possible states of a job.
        """
        INITIALISED = 'initialised'
        RUNNING = 'running'
        FAILED = 'failed'
        TIMEOUT = 'timeout'
        SUCCESSFUL = 'successful'

    class Error(BaseModel):
        """
        Information about an error.
        """
        message: str = Field(..., title="Message", description="A simple message indicating the nature of the problem.")
        exception: ExceptionContent = Field(..., title="Exception", description="Detailed information about an exception that occured during job execution.")

    state: Literal[State.INITIALISED, State.RUNNING, State.FAILED, State.TIMEOUT, State.SUCCESSFUL] = Field(..., title="State", description="The state of the job.")
    progress: int = Field(..., title="Progress", description="An integer value indicating the progress in %.", example=55)
    output: Dict[str, CDataObject] = Field(..., title="Output", description="A mapping of product names (i.e., the outputs of the job) and the corresponding object meta information.")
    notes: dict = Field(..., title="Notes", description="Any notes that may have been logged during the execution.")
    job: Job = Field(..., title="Job", description="The job information.")
    reconnect: Optional[ReconnectInfo] = Field(title="Reconnect Info", description="Information that would allow the user to reconnect to a job in case the connection was lost.")
    errors: Optional[List[Error]] = Field(title="Errors", description="A list of errors that occurred during job execution (if any)")


class Processor(BaseModel):
    """
    Information about a deployed processor. This includes its id and the GPP.
    """
    proc_id: str = Field(..., title="Processor Id", description="The processor id.", example="d01d069675bcaaeb90b46273ccc4ae9818a2667957045d0f0f15901ffcf807de")
    gpp: GitProcessorPointer = Field(..., title="GPP", description="The Git Processor Pointer information.")


class ProcessorStatus(BaseModel):
    """
    Status information about a deployed processor.
    """
    state: str = Field(..., title="State", description="The state of the processor.", example="initialised")
    pending: List[Job] = Field(..., title="Pending Jobs", description="A list of pending jobs that are queued for execution.")
    active: Optional[Job] = Field(title="Active Job", description="The job that is currently being executed by the processor (if any).")
