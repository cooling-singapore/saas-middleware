import json
from enum import unique, Enum
from typing import List, Optional

from flask import Response
from pydantic import BaseModel

from saas.keystore.assets.credentials import SSHCredentials, GithubCredentials
from saas.keystore.identity import Identity
from saas.logging import Logging
from saas.rest.blueprint import SaaSBlueprint, create_ok_response
from saas.rest.proxy import EndpointProxy
from saas.rest.request_manager import request_manager
from saas.schemas import JobDescriptor, ProcessorDescriptor, TaskDescriptor

import saas.nodedb.blueprint as nodedb_bp

logger = Logging.get('rti.blueprint')
endpoint_prefix = "/api/v1/processor"


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
        super().__init__('processor', __name__, endpoint_prefix)
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
            github_credentials = bytes.fromhex(body['ssh_credentials'])
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


class RTIProxy(EndpointProxy):
    def __init__(self, remote_address: (str, int)) -> None:
        EndpointProxy.__init__(self, endpoint_prefix, remote_address)

    def get_deployed(self):
        return self.get(f"")

    def deploy(self, proc_id: str, deployment: str = "native", gpp_custodian: str = None,
               ssh_credentials: SSHCredentials = None, github_credentials: GithubCredentials = None) -> dict:

        body = {
            'deployment': deployment,
        }

        if gpp_custodian:
            body['gpp_custodian'] = gpp_custodian

        # do we have credentials to encrypt?
        if ssh_credentials or github_credentials:
            # get info about the node (TODO: there is probably a better way to get the id of the peer)
            db = nodedb_bp.NodeDBProxy(self.remote_address)
            peer_info = db.get_node()
            peer = Identity.deserialise(peer_info['identity'])

            if ssh_credentials:
                ssh_credentials_serialised = json.dumps({
                    'host': ssh_credentials.host,
                    'login': ssh_credentials.login,
                    'key': ssh_credentials.key,
                    'key_is_password': ssh_credentials.key_is_password
                })
                body['ssh_credentials'] = peer.encrypt(ssh_credentials_serialised.encode('utf-8')).hex()

            if github_credentials:
                github_credentials_serialised = json.dumps({
                    'login': github_credentials.login,
                    'personal_access_token': github_credentials.personal_access_token
                })
                body['github_credentials'] = peer.encrypt(github_credentials_serialised.encode('utf-8')).hex()

        return self.post(f"/{proc_id}", body=body)

    def undeploy(self, proc_id: str) -> dict:
        return self.delete(f"/{proc_id}")

    def get_descriptor(self, proc_id: str) -> dict:
        return self.get(f"/{proc_id}/descriptor")

    def submit_job(self, proc_id: str, job_input: list, job_output: list, user: Identity) -> dict:
        return self.post(f"/{proc_id}/jobs", body={
            'processor_id': proc_id,
            'input': job_input,
            'output': job_output,
            'user_iid': user.id
        })

    def get_jobs(self, proc_id: str) -> dict:
        return self.get(f"/{proc_id}/jobs")

    def get_job_info(self, job_id: str) -> (dict, dict):
        r = self.get(f"/job/{job_id}")
        return r['job_descriptor'], r['status']

    def put_permission(self, req_id: str, permission: str) -> None:
        self.post(f"/permission/{req_id}", body=permission)
