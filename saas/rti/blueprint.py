import logging

from flask import Blueprint, jsonify

from saas.keystore.identity import Identity
from saas.rest.proxy import EndpointProxy
from saas.rest.request_manager import request_manager
from saas.schemas import task_descriptor_schema

logger = logging.getLogger('rti.blueprint')
endpoint_prefix = "/api/v1/processor"

put_permission_body_schema = {
    'type': 'string'
}

deployment_specification = {
    'type': 'object',
    'properties': {
        'deployment': {'type': 'string', 'enum': ['native', 'docker']},
    },
    'required': ['deployment']
}


class RTIBlueprint:
    def __init__(self, node):
        self._node = node

    def blueprint(self):
        blueprint = Blueprint('processor', __name__, url_prefix=endpoint_prefix)
        blueprint.add_url_rule('', self.get_deployed.__name__, self.get_deployed, methods=['GET'])
        blueprint.add_url_rule('/<proc_id>', self.deploy.__name__, self.deploy, methods=['POST'])
        blueprint.add_url_rule('/<proc_id>', self.undeploy.__name__, self.undeploy, methods=['DELETE'])
        blueprint.add_url_rule('/<proc_id>/descriptor', self.get_descriptor.__name__, self.get_descriptor, methods=['GET'])
        blueprint.add_url_rule('/<proc_id>/jobs', self.submit_job.__name__, self.submit_job, methods=['POST'])
        blueprint.add_url_rule('/<proc_id>/jobs', self.get_jobs.__name__, self.get_jobs, methods=['GET'])
        blueprint.add_url_rule('/job/<job_id>', self.get_job_info.__name__, self.get_job_info, methods=['GET'])
        blueprint.add_url_rule('/permission/<req_id>', self.put_permission.__name__, self.put_permission, methods=['POST'])
        return blueprint

    def get_deployed(self):
        return jsonify(self._node.rti.get_deployed()), 200

    @request_manager.verify_request_body(deployment_specification)
    def deploy(self, proc_id):
        # TODO: this should require authorisation - only whose authorisation? probably by the identity of the node.
        body = request_manager.get_request_variable('body')
        deployment = body['deployment']
        descriptor = self._node.rti.deploy(proc_id, deployment)
        if descriptor:
            return jsonify(descriptor), 201
        else:
            return jsonify(proc_id), 404

    def undeploy(self, proc_id):
        # TODO: this should require authorisation - only whose authorisation? probably by the identity of the node.
        if self._node.rti.undeploy(proc_id):
            return jsonify(proc_id), 200
        else:
            return jsonify(proc_id), 404

    def get_descriptor(self, proc_id):
        descriptor = self._node.rti.get_descriptor(proc_id)
        if descriptor:
            return jsonify(descriptor), 200

        else:
            return jsonify(proc_id), 404

    @request_manager.verify_request_body(task_descriptor_schema)
    def submit_job(self, proc_id):
        task_descriptor = request_manager.get_request_variable('body')

        job_id = self._node.rti.submit(proc_id, task_descriptor)
        if job_id is not None:
            return jsonify(job_id), 201
        else:
            return jsonify(proc_id), 404

    def get_jobs(self, proc_id):
        jobs = self._node.rti.get_jobs(proc_id)
        if jobs is not None:
            return jsonify(jobs), 200
        else:
            return jsonify(proc_id), 404

    def get_job_info(self, job_id):
        job_info = self._node.rti.get_job_info(job_id)
        if job_info:
            return jsonify({
                'job_descriptor': job_info['job_descriptor'],
                'status': job_info['status']
            }), 200
        else:
            return jsonify(job_id), 404

    @request_manager.verify_request_body(put_permission_body_schema)
    def put_permission(self, req_id):
        permission = request_manager.get_request_variable('body')
        self._node.rti.put_permission(req_id, permission)

        return jsonify(req_id), 201


class RTIProxy(EndpointProxy):
    def __init__(self, remote_address):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address)

    def get_deployed(self):
        code, r = self.get(f"")
        return r

    def deploy(self, proc_id, deployment="native"):
        body = {
            'deployment': deployment,
        }

        code, r = self.post(f"/{proc_id}", body=body)
        return r if code == 201 else None

    def undeploy(self, proc_id):
        code, r = self.delete(f"/{proc_id}")
        return r if code == 200 else None

    def get_descriptor(self, proc_id):
        code, r = self.get(f"/{proc_id}/descriptor")
        return r if code == 200 else None

    def submit_job(self, proc_id: str, job_input: list, job_output: list, user: Identity):
        body = {
            'processor_id': proc_id,
            'input': job_input,
            'output': job_output,
            'user_iid': user.id
        }

        code, r = self.post(f"/{proc_id}/jobs", body=body)
        return r

    def get_jobs(self, proc_id):
        code, r = self.get(f"/{proc_id}/jobs")
        return r

    def get_job_info(self, job_id):
        code, r = self.get(f"/job/{job_id}")
        if code == 200:
            return r['job_descriptor'], r['status']
        else:
            return None, None

    def put_permission(self, req_id, permission):
        code, r = self.post(f"/permission/{req_id}", body=permission)
        return r
