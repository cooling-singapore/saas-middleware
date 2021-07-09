import logging
import os

from flask import Blueprint, jsonify

from saas.rest.proxy import EndpointProxy
from saas.utilities.blueprint_helpers import request_manager
from saas.schemas import task_descriptor_schema
from saas.utilities.general_helpers import all_in_dict, load_json_from_file

logger = logging.getLogger('rti.blueprint')
endpoint_prefix = "/api/v1/processor"

put_permission_body_schema = {
    'permission': {'type': 'string'}
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

    @request_manager.authentication_required
    def get_deployed(self):
        return jsonify({
            'deployed': self._node.rti.get_deployed()
        }), 200

    @request_manager.authentication_required
    def deploy(self, proc_id):
        # TODO: this should require authorisation - only whose authorisation? probably by the identity of the node.
        descriptor = self._node.rti.deploy(proc_id)
        if descriptor:
            return jsonify(descriptor), 201
        else:
            return jsonify(f"Processor {proc_id} not found."), 404

    @request_manager.authentication_required
    def undeploy(self, proc_id):
        # TODO: this should require authorisation - only whose authorisation? probably by the identity of the node.
        if self._node.rti.undeploy(proc_id):
            return jsonify(f"Processor {proc_id} undeployed."), 200
        else:
            return jsonify(f"Processor {proc_id} not found."), 404

    @request_manager.authentication_required
    def get_descriptor(self, proc_id):
        descriptor_path = self._node.rti.proc_descriptor_path(proc_id)
        if os.path.isfile(descriptor_path):
            return jsonify(load_json_from_file(descriptor_path)), 200

        else:
            return jsonify(f"Processor {proc_id} not found."), 404

    @request_manager.authentication_required
    @request_manager.verify_request_body(task_descriptor_schema)
    def submit_job(self, proc_id):
        task_descriptor = request_manager.get_request_variable('body')

        job_id = self._node.rti.submit(proc_id, task_descriptor)
        if job_id is not None:
            return jsonify({
                'job_id': job_id
            }), 201
        else:
            return jsonify(f"Processor {proc_id} not deployed."), 404

    @request_manager.authentication_required
    def get_jobs(self, proc_id):
        jobs = self._node.rti.get_jobs(proc_id)
        if jobs is not None:
            return jsonify({
                'jobs': jobs
            }), 200
        else:
            return jsonify(f"Processor {proc_id} not deployed."), 404

    @request_manager.authentication_required
    def get_job_info(self, job_id):
        job_info = self._node.rti.get_job_info(job_id)
        if job_info:
            return jsonify({
                'job_descriptor': job_info['job_descriptor'],
                'status': job_info['status']
            }), 200
        else:
            return jsonify(f"No job with id {job_id}."), 404

    @request_manager.authentication_required
    @request_manager.verify_request_body(put_permission_body_schema)
    def put_permission(self, req_id):
        body = request_manager.get_request_variable('body')
        self._node.rti.put_permission(req_id, body['permission'])

        return jsonify("Ok."), 201


class RTIProxy(EndpointProxy):
    def __init__(self, remote_address, sender):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address, sender)

    def get_deployed(self):
        r = self.get(f"")
        return r['reply']['deployed'] if 'deployed' in r['reply'] else None

    def deploy(self, proc_id):
        r = self.post(f"/{proc_id}")
        return r['reply']

    def undeploy(self, proc_id):
        r = self.delete(f"/{proc_id}")
        return r

    def get_descriptor(self, proc_id):
        r = self.get(f"/{proc_id}/descriptor")
        return r['reply']

    def submit_job(self, proc_id, job_input, job_output, user):
        body = {
            'processor_id': proc_id,
            'input': job_input,
            'output': job_output,
            'user_iid': user.id()
        }

        r = self.post(f"/{proc_id}/jobs", body=body)
        return r['reply']['job_id'] if 'job_id' in r['reply'] else None

    def get_jobs(self, proc_id):
        r = self.get(f"/{proc_id}/jobs")
        return r['reply']['jobs'] if 'jobs' in r['reply'] else None

    def get_job_info(self, job_id):
        r = self.get(f"/job/{job_id}")
        if not all_in_dict(['job_descriptor', 'status'], r['reply']):
            return None

        return r['reply']['job_descriptor'], r['reply']['status']

    def put_permission(self, req_id, permission):
        body = {
            'permission': permission,
        }

        r = self.post(f"/permission/{req_id}", body=body)
        return r['reply']
