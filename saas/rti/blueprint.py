"""
Flask blueprint for the SaaS Runtime Infrastructure.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging

from flask import Blueprint, jsonify
from flask_cors import CORS

from saas.utilities.blueprint_helpers import request_manager
from saas.json_schemas import task_descriptor_schema, workflow_descriptor_schema
from saas.node import Node

# create the blueprint object and allows CORS for the processor route
blueprint = Blueprint('processor', __name__)
CORS(blueprint)

logger = logging.getLogger('RTI.Blueprint')
node: Node


def initialise(node_instance):
    global node
    node = node_instance


@blueprint.route('', methods=['GET'])
@request_manager.authentication_required
def get_deployed():
    return jsonify({
        'deployed': node.rti.get_deployed()
    }), 200


@blueprint.route('/<proc_id>', methods=['POST'])
@request_manager.authentication_required
def deploy(proc_id):
    # TODO: this should require authorisation - only whose authorisation?
    descriptor = node.rti.deploy(proc_id)
    if descriptor:
        return jsonify({
            'descriptor': descriptor
        }), 201
    else:
        return jsonify(f"Processor {proc_id} not found."), 404


@blueprint.route('/<proc_id>', methods=['DELETE'])
@request_manager.authentication_required
def undeploy(proc_id):
    # TODO: this should require authorisation - only whose authorisation?
    if node.rti.undeploy(proc_id):
        return jsonify(f"Processor {proc_id} undeployed."), 200
    else:
        return jsonify(f"Processor {proc_id} not found."), 404


@blueprint.route('/<proc_id>', methods=['GET'])
@blueprint.route('/<proc_id>/descriptor', methods=['GET'])
@request_manager.authentication_required
def get_descriptor(proc_id):
    try:
        descriptor = node.rti.get_descriptor(proc_id)
        return jsonify({
            'descriptor': descriptor
        }), 200
    except FileNotFoundError:
        pass

    return jsonify(f"Processor {proc_id} not found."), 404


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


@blueprint.route('/<proc_id>/jobs', methods=['POST'])
@request_manager.authentication_required
@request_manager.verify_request_body(job_body_specification)
def submit_job(proc_id):
    body = request_manager.get_request_variable('body')

    # determine processor descriptor and id, then submit the job
    descriptor = body['descriptor']
    proc_id = descriptor['processor_id'] if body['type'] == 'task' else 'workflow'
    job_id = node.rti.submit(proc_id, descriptor)
    if job_id is not None:
        return jsonify({
            'job_id': job_id
        }), 201
    else:
        return jsonify(f"Processor {proc_id} not deployed."), 404


@blueprint.route('/<proc_id>/jobs', methods=['GET'])
@request_manager.authentication_required
def get_jobs(proc_id):
    jobs = node.rti.get_jobs(proc_id)
    if jobs is not None:
        return jsonify({
            'jobs': jobs
        }), 200
    else:
        return jsonify(f"Processor {proc_id} not deployed."), 404


@blueprint.route('/<proc_id>/jobs/<job_id>', methods=['GET'])
@request_manager.authentication_required
def get_job(proc_id, job_id):
    job_info = node.rti.get_job(job_id)
    if job_info:
        return jsonify({
            'job_descriptor': job_info['job_descriptor'],
            'status': job_info['status']
        }), 200
    else:
        return jsonify(f"No job with id {job_id}."), 404
