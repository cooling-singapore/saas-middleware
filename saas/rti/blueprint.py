"""
Flask blueprint for the SaaS Runtime Infrastructure.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging

from flask import Blueprint, request
from flask_cors import CORS

from saas.utilities.blueprint_helpers import create_signed_response
from saas.utilities.blueprint_helpers import verify_request_authentication, verify_request_body
from saas.utilities.blueprint_helpers import RequestError
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


@blueprint.route('/', methods=['GET'])
def get_deployed():
    url = "GET:/processor"
    try:
        # verification of authentication: required
        verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: not required

        return create_signed_response(node, url, 200, {
            'deployed': node.rti.get_deployed()
        })

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<proc_id>', methods=['POST'])
def deploy(proc_id):
    url = "POST:/processor/{}".format(proc_id)
    try:
        # verification of authentication: required
        verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: not required
        # TODO: this should require authorisation - only whose authorisation?

        descriptor = node.rti.deploy(proc_id)
        if descriptor:
            return create_signed_response(node, url, 201, {
                'descriptor': descriptor
            })
        else:
            return create_signed_response(node, url, 404, "Processor {} not found.".format(proc_id))

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<proc_id>', methods=['DELETE'])
def undeploy(proc_id):
    url = "DELETE:/processor/{}".format(proc_id)
    try:
        # verification of authentication: required
        verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: not required
        # TODO: this should require authorisation - only whose authorisation?

        if node.rti.undeploy(proc_id):
            return create_signed_response(node, url, 200)
        else:
            return create_signed_response(node, url, 404, "Processor {} not deployed.".format(proc_id))

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/processor/<proc_id>', methods=['GET'])
@blueprint.route('/processor/<proc_id>/descriptor', methods=['GET'])
def get_descriptor(proc_id):
    url = "GET:/processor/{}/descriptor".format(proc_id)

    try:
        # verification of authentication: required
        verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: not required

        descriptor = node.rti.get_descriptor(proc_id)
        if descriptor:
            return create_signed_response(node, url, 200, {
                'descriptor': descriptor
            })
        else:
            return create_signed_response(node, url, 404, "Processor {} not deployed.".format(proc_id))

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<proc_id>/jobs', methods=['POST'])
def submit_job(proc_id):
    url = "POST:/processor/{}/jobs".format(proc_id)
    body_specification = {
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

    try:
        # verification of authentication: required
        body, files = verify_request_authentication(url, request)

        # verification of contents: not required
        logger.info("body: {}".format(body))
        logger.info("body_specification: {}".format(body_specification))
        verify_request_body(body, body_specification)

        # verification of authorisation: not required

        # determine processor descriptor and id, then submit the job
        descriptor = body['descriptor']
        proc_id = descriptor['processor_id'] if body['type'] == 'task' else 'workflow'
        job_id = node.rti.submit(proc_id, descriptor)
        if job_id is not None:
            return create_signed_response(node, url, 201, {
                'job_id': job_id
            })
        else:
            return create_signed_response(node, url, 404, "Processor {} not deployed.".format(proc_id))

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<proc_id>/jobs', methods=['GET'])
def get_jobs(proc_id):
    url = "GET:/processor/{}/jobs".format(proc_id)

    try:
        # verification of authentication: required
        verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: not required

        jobs = node.rti.get_jobs(proc_id)
        if jobs is not None:
            return create_signed_response(node, url, 200, {
                'jobs': jobs
            })
        else:
            return create_signed_response(node, url, 404, "Processor {} not deployed.".format(proc_id))

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<proc_id>/jobs/<job_id>', methods=['GET'])
def get_job(proc_id, job_id):
    url = "GET:/processor/{}/jobs/{}".format(proc_id, job_id)

    try:
        # verification of authentication: required
        verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: not required

        job_descriptor, status = node.rti.get_job(job_id)
        if job_descriptor:
            return create_signed_response(node, url, 200, {
                'job_descriptor': job_descriptor,
                'status': status
            })
        else:
            return create_signed_response(node, url, 404, "No job with id {}.".format(job_id))

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)
