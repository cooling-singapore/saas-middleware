from enum import Enum, unique
from typing import Optional

from pydantic import BaseModel

from saas.schemas import JobDescriptor, ProcessorDescriptor


class ProcessorDeploymentParameters(BaseModel):
    @unique
    class ProcessorDeploymentType(str, Enum):
        native = 'native'
        docker = 'docker'

    deployment: ProcessorDeploymentType
    ssh_credentials: Optional[str]
    github_credentials: Optional[str]
    gpp_custodian: Optional[str]


class DeployedProcessorInfo(BaseModel):
    proc_id: str
    proc_descriptor: ProcessorDescriptor


class JobInfo(BaseModel):
    job_descriptor: JobDescriptor
    status: dict
    reconnect_info: Optional[dict]


class Permission(BaseModel):
    req_id: str
    content_key: str
