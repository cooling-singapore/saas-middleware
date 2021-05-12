import logging

from flask import Blueprint, jsonify
from flask_cors import CORS

from saas.rest.proxy import EndpointProxy
from saas.utilities.blueprint_helpers import request_manager
from saas.schemas import task_descriptor_schema, workflow_descriptor_schema
from saas.utilities.general_helpers import all_in_dict

logger = logging.getLogger('rti.blueprint')
endpoint_prefix = "/api/v1/processor"

job_body_specification = {
    'type': 'object',
    'properties': {
        'type': {'type': 'string', 'enum': ['workflow', 'task']},
    },
    'if': {
        'properties': {'type': {'const': 'workflow'}}
    },
    'then': {
        'properties': {
            'descriptor': workflow_descriptor_schema
        }
    },
    'else': {
        'properties': {
            'descriptor': task_descriptor_schema
        }
    },
    'required': ['type', 'descriptor']
}


class RTIBlueprint:
    def __init__(self, node):
        self._node = node

    def blueprint(self):
        # create the blueprint and allow CORS for the processor route
        blueprint = Blueprint('processor', __name__, url_prefix=endpoint_prefix)
        blueprint.add_url_rule('', self.get_deployed.__name__, self.get_deployed, methods=['GET'])
        blueprint.add_url_rule('/<proc_id>', self.deploy.__name__, self.deploy, methods=['POST'])
        blueprint.add_url_rule('/<proc_id>', self.undeploy.__name__, self.undeploy, methods=['DELETE'])
        blueprint.add_url_rule('/<proc_id>/descriptor', self.get_descriptor.__name__, self.get_descriptor, methods=['GET'])
        blueprint.add_url_rule('/<proc_id>/jobs', self.submit_job.__name__, self.submit_job, methods=['POST'])
        blueprint.add_url_rule('/<proc_id>/jobs', self.get_jobs.__name__, self.get_jobs, methods=['GET'])
        blueprint.add_url_rule('/<proc_id>/jobs/<job_id>', self.get_job_info.__name__, self.get_job_info, methods=['GET'])
        CORS(blueprint)
        return blueprint

    @request_manager.authentication_required
    def get_deployed(self):
        return jsonify({
            'deployed': self._node.rti.get_deployed()
        }), 200

    @request_manager.authentication_required
    def deploy(self, proc_id):
        # TODO: this should require authorisation - only whose authorisation?
        descriptor = self._node.rti.deploy(proc_id)
        if descriptor:
            return jsonify({
                'descriptor': descriptor
            }), 201
        else:
            return jsonify(f"Processor {proc_id} not found."), 404

    @request_manager.authentication_required
    def undeploy(self, proc_id):
        # TODO: this should require authorisation - only whose authorisation?
        if self._node.rti.undeploy(proc_id):
            return jsonify(f"Processor {proc_id} undeployed."), 200
        else:
            return jsonify(f"Processor {proc_id} not found."), 404

    @request_manager.authentication_required
    def get_descriptor(self, proc_id):
        try:
            descriptor = self._node.rti.get_descriptor(proc_id)
            return jsonify({
                'descriptor': descriptor
            }), 200
        except FileNotFoundError:
            pass

        return jsonify(f"Processor {proc_id} not found."), 404

    @request_manager.authentication_required
    @request_manager.verify_request_body(job_body_specification)
    def submit_job(self, proc_id):
        body = request_manager.get_request_variable('body')

        # determine processor descriptor and id, then submit the job
        descriptor = body['descriptor']
        proc_id = descriptor['processor_id'] if body['type'] == 'task' else 'workflow'
        job_id = self._node.rti.submit(proc_id, descriptor)
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
    def get_job_info(self, proc_id, job_id):
        job_info = self._node.rti.get_job_info(job_id)
        if job_info:
            return jsonify({
                'job_descriptor': job_info['job_descriptor'],
                'status': job_info['status']
            }), 200
        else:
            return jsonify(f"No job with id {job_id}."), 404


class RTIProxy(EndpointProxy):
    def __init__(self, remote_address, sender):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address, sender)

    def get_deployed(self):
        r = self.get(f"")
        return r['reply']['deployed'] if 'deployed' in r['reply'] else None

    def deploy(self, proc_id):
        r = self.post(f"/{proc_id}")
        return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None

    def undeploy(self, proc_id):
        r = self.delete(f"/{proc_id}")
        return r

    def get_descriptor(self, proc_id):
        r = self.get(f"/{proc_id}/descriptor")
        return r['reply']['descriptor']

    def submit_job(self, proc_id, proc_input, output_owner):
        body = {
            'type': 'task',
            'descriptor': {
                'processor_id': proc_id,
                'input': proc_input,
                'output': {
                    'owner_public_key': output_owner.public_as_string()
                }
            }
        }

        r = self.post(f"/{proc_id}/jobs", body=body)
        return r['reply']['job_id'] if 'job_id' in r['reply'] else None

    def submit_workflow(self, name, tasks):
        body = {
            'type': 'workflow',
            'descriptor': {
                'name': name,
                'tasks': tasks
            }
        }

        r = self.post(f"/workflow/jobs", body=body)
        return r['reply']['job_id'] if 'job_id' in r['reply'] else None

    def submit_task(self, proc_id, input_descriptor, owner):
        input_descriptor_array = []
        for item in input_descriptor.items():
            input_descriptor_array.append(item[1])

        body = {
            'type': 'task',
            'descriptor': {
                'processor_id': proc_id,
                'input': input_descriptor_array,
                'output': {
                    'owner_public_key': owner.public_as_string()
                }
            }
        }

        r = self.post(f"/{proc_id}/jobs", body=body)
        return r['reply']['job_id'] if 'job_id' in r['reply'] else None

    def get_jobs(self, proc_id):
        r = self.get(f"/{proc_id}/jobs")
        return r['reply']['jobs'] if 'jobs' in r['reply'] else None

    def get_job_info(self, proc_id, job_id):
        r = self.get(f"/{proc_id}/jobs/{job_id}")
        if not all_in_dict(['job_descriptor', 'status'], r['reply']):
            return None

        return r['reply']['job_descriptor'], r['reply']['status']
