import json
from enum import unique, Enum
from typing import List, Optional

from flask import Response
from pydantic import BaseModel
from saascore.api.sdk.helpers import create_ok_response
from saascore.api.sdk.proxies import rti_endpoint_prefix

from saascore.keystore.assets.credentials import SSHCredentials, GithubCredentials
from saascore.log import Logging

from saas.rest.blueprint import SaaSBlueprint
from saas.rest.request_manager import request_manager
from saas.schemas import JobDescriptor, ProcessorDescriptor, TaskDescriptor

logger = Logging.get('rti.blueprint')


class ProcessorDeploymentParameters(BaseModel):
    @unique
    class ProcessorDeploymentType(str, Enum):
        native = 'native'
        docker = 'docker'

    deployment: ProcessorDeploymentType
    ssh_credentials: Optional[str]
    github_credentials: Optional[str]
    gpp_custodian: Optional[str]


class DeployedProcessors(BaseModel):
    class DeployedProcessor(BaseModel):
        proc_id: str
        proc_descriptor: ProcessorDescriptor

    __root__: List[DeployedProcessor]


class JobDescriptors(BaseModel):
    __root__: List[JobDescriptor]


class JobStatus(BaseModel):
    job_descriptor: JobDescriptor
    status: dict


class ContentKey(BaseModel):
    __root__: str


class RTIBlueprint(SaaSBlueprint):
    def __init__(self, node) -> None:
        super().__init__('processor', __name__, rti_endpoint_prefix)
        self._node = node

        self.add_rule('', self.get_deployed, ['GET'])
        self.add_rule('<proc_id>', self.deploy, ['POST'])
        self.add_rule('<proc_id>', self.undeploy, ['DELETE'])
        self.add_rule('<proc_id>/descriptor', self.get_descriptor, ['GET'])
        self.add_rule('<proc_id>/jobs', self.submit_job, ['POST'])
        self.add_rule('<proc_id>/jobs', self.get_jobs, ['GET'])
        self.add_rule('job/<job_id>', self.get_job_info, ['GET'])
        self.add_rule('permission/<req_id>', self.put_permission, ['POST'])

    @request_manager.handle_request(DeployedProcessors)
    @request_manager.require_rti()
    def get_deployed(self) -> (Response, int):
        return create_ok_response(self._node.rti.get_deployed())

    @request_manager.handle_request(ProcessorDescriptor)
    @request_manager.require_rti()
    @request_manager.verify_request_body(ProcessorDeploymentParameters)
    def deploy(self, proc_id: str) -> (Response, int):
        # TODO: this should require authorisation - only whose authorisation? probably by the identity of the node.
        body = request_manager.get_request_variable('body')
        gpp_custodian = body['gpp_custodian'] if 'gpp_custodian' in body else None

        if 'ssh_credentials' in body:
            ssh_credentials = bytes.fromhex(body['ssh_credentials'])
            ssh_credentials = self._node.keystore.decrypt(ssh_credentials)
            ssh_credentials = ssh_credentials.decode('utf-8')
            ssh_credentials = json.loads(ssh_credentials)
            ssh_credentials = SSHCredentials(host=ssh_credentials['host'],
                                             login=ssh_credentials['login'],
                                             key=ssh_credentials['key'],
                                             key_is_password=ssh_credentials['key_is_password'])
        else:
            ssh_credentials = None

        if 'github_credentials' in body:
            github_credentials = bytes.fromhex(body['github_credentials'])
            github_credentials = self._node.keystore.decrypt(github_credentials)
            github_credentials = github_credentials.decode('utf-8')
            github_credentials = json.loads(github_credentials)
            github_credentials = GithubCredentials(login=github_credentials['login'],
                                                   personal_access_token=github_credentials['personal_access_token'])

        else:
            github_credentials = None

        return create_ok_response(self._node.rti.deploy(proc_id,
                                                        deployment=body['deployment'],
                                                        ssh_credentials=ssh_credentials,
                                                        github_credentials=github_credentials,
                                                        gpp_custodian=gpp_custodian))

    @request_manager.handle_request(ProcessorDescriptor)
    @request_manager.require_rti()
    def undeploy(self, proc_id: str) -> (Response, int):
        return create_ok_response(self._node.rti.undeploy(proc_id))

    @request_manager.handle_request(ProcessorDescriptor)
    @request_manager.require_rti()
    def get_descriptor(self, proc_id: str) -> (Response, int):
        return create_ok_response(self._node.rti.get_descriptor(proc_id))

    @request_manager.handle_request(JobDescriptor)
    @request_manager.require_rti()
    @request_manager.verify_request_body(TaskDescriptor)
    def submit_job(self, proc_id: str) -> (Response, int):
        task_descriptor = request_manager.get_request_variable('body')
        return create_ok_response(self._node.rti.submit(proc_id, task_descriptor))

    @request_manager.handle_request(JobDescriptors)
    @request_manager.require_rti()
    def get_jobs(self, proc_id: str) -> (Response, int):
        return create_ok_response(self._node.rti.get_jobs(proc_id))

    @request_manager.handle_request(JobStatus)
    @request_manager.require_rti()
    def get_job_info(self, job_id: str) -> (Response, int):
        job_info = self._node.rti.get_job_info(job_id)
        return create_ok_response({
            'job_descriptor': job_info['job_descriptor'],
            'status': job_info['status']
        })

    @request_manager.handle_request()
    @request_manager.require_rti()
    @request_manager.verify_request_body(ContentKey)
    def put_permission(self, req_id: str) -> (Response, int):
        permission = request_manager.get_request_variable('body')
        self._node.rti.put_permission(req_id, permission)
        return create_ok_response()
