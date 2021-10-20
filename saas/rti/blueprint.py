from flask import Response

from saas.keystore.assets.credentials import SSHCredentials, GithubCredentials
from saas.keystore.identity import Identity
from saas.logging import Logging
from saas.rest.blueprint import SaaSBlueprint, create_ok_response
from saas.rest.proxy import EndpointProxy
from saas.rest.request_manager import request_manager
from saas.schemas import task_descriptor_schema, job_descriptor_schema, processor_descriptor_schema

logger = Logging.get('rti.blueprint')
endpoint_prefix = "/api/v1/processor"

deployed_processors_schema = {
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'proc_id': {'type': 'string'},
            'proc_descriptor': processor_descriptor_schema
        },
        'required': ['proc_id', 'proc_descriptor']
    }
}

put_permission_body_schema = {
    'type': 'string'
}

deployment_specification = {
    'type': 'object',
    'properties': {
        'deployment': {'type': 'string', 'enum': ['native', 'docker']},
        'ssh_credentials': {
            'type': 'object',
            'properties': {
                'host': {'type': 'string'},
                'login': {'type': 'string'},
                'key': {'type': 'string'}
            },
            'required': ['host', 'login', 'key']
        },
        'github_credentials': {
            'type': 'object',
            'properties': {
                'login': {'type': 'string'},
                'personal_access_token': {'type': 'string'}
            },
            'required': ['login', 'personal_access_token']
        },
        'gpp_custodian': {'type': 'string'}
    },
    'required': ['deployment']
}

jobs_descriptor_schema = {
    'type': 'array',
    'items': job_descriptor_schema
}

job_details_schema = {
    'type': 'object',
    'properties': {
        'job_descriptor': job_descriptor_schema,
        'status': {'type': 'object'}
    },
    'required': ['job_descriptor', 'status']
}


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

    @request_manager.handle_request(deployed_processors_schema)
    @request_manager.require_rti()
    def get_deployed(self) -> (Response, int):
        return create_ok_response(self._node.rti.get_deployed())

    @request_manager.handle_request(processor_descriptor_schema)
    @request_manager.require_rti()
    @request_manager.verify_request_body(deployment_specification)
    def deploy(self, proc_id: str) -> (Response, int):
        # TODO: this should require authorisation - only whose authorisation? probably by the identity of the node.
        body = request_manager.get_request_variable('body')
        gpp_custodian = body['gpp_custodian'] if 'gpp_custodian' in body else None
        ssh_credentials = SSHCredentials(host=body['ssh_credentials']['host'],
                                         login=body['ssh_credentials']['login'],
                                         key=body['ssh_credentials']['key']) if 'ssh_credentials' in body else None

        github_credentials = GithubCredentials(login=body['github_credentials']['login'],
                                               personal_access_token=body['github_credentials']['personal_access_token']) \
            if 'github_credentials' in body else None

        return create_ok_response(self._node.rti.deploy(proc_id,
                                                        deployment=body['deployment'],
                                                        ssh_credentials=ssh_credentials,
                                                        github_credentials=github_credentials,
                                                        gpp_custodian=gpp_custodian))

    @request_manager.handle_request(processor_descriptor_schema)
    @request_manager.require_rti()
    def undeploy(self, proc_id: str) -> (Response, int):
        return create_ok_response(self._node.rti.undeploy(proc_id))

    @request_manager.handle_request(processor_descriptor_schema)
    @request_manager.require_rti()
    def get_descriptor(self, proc_id: str) -> (Response, int):
        return create_ok_response(self._node.rti.get_descriptor(proc_id))

    @request_manager.handle_request(job_descriptor_schema)
    @request_manager.require_rti()
    @request_manager.verify_request_body(task_descriptor_schema)
    def submit_job(self, proc_id: str) -> (Response, int):
        task_descriptor = request_manager.get_request_variable('body')
        return create_ok_response(self._node.rti.submit(proc_id, task_descriptor))

    @request_manager.handle_request(jobs_descriptor_schema)
    @request_manager.require_rti()
    def get_jobs(self, proc_id: str) -> (Response, int):
        return create_ok_response(self._node.rti.get_jobs(proc_id))

    @request_manager.handle_request(job_details_schema)
    @request_manager.require_rti()
    def get_job_info(self, job_id: str) -> (Response, int):
        job_info = self._node.rti.get_job_info(job_id)
        return create_ok_response({
            'job_descriptor': job_info['job_descriptor'],
            'status': job_info['status']
        })

    @request_manager.handle_request(None)
    @request_manager.require_rti()
    @request_manager.verify_request_body(put_permission_body_schema)
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

        if ssh_credentials:
            body['ssh_credentials'] = {
                'host': ssh_credentials.host,
                'login': ssh_credentials.login,
                'key': ssh_credentials.key
            }

        if github_credentials:
            body['github_credentials'] = {
                'login': github_credentials.login,
                'personal_access_token': github_credentials.personal_access_token
            }

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
