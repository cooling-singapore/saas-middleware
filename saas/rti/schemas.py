from enum import Enum, unique
from typing import Optional

from pydantic import BaseModel

from saas.schemas import JobDescriptor, GitProcessorPointer


class DeployParameters(BaseModel):
    @unique
    class ProcessorDeploymentType(str, Enum):
        native = 'native'
        docker = 'docker'

    deployment: ProcessorDeploymentType
    ssh_credentials: Optional[str]
    github_credentials: Optional[str]
    gpp_custodian: Optional[str]


class Processor(BaseModel):
    proc_id: str
    gpp: GitProcessorPointer


class Job(BaseModel):
    descriptor: JobDescriptor
    status: dict
    reconnect_info: Optional[dict]


class Permission(BaseModel):
    req_id: str
    content_key: str
