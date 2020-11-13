"""
Flask blueprint for the SaaS Data Object Repository service.
"""

import os
import json
import tempfile
import logging

from jsonschema import validate

from flask import Blueprint, jsonify, abort, request, send_from_directory
from flask_cors import CORS

from dor import DataObjectRepository

# create the blueprint object and allows CORS for the processor route
blueprint = Blueprint('repository', __name__)
CORS(blueprint)

logger = logging.getLogger('DOR:blueprint')
instance: DataObjectRepository = None


def validate_json_schemas(validation_cases):
    for case in validation_cases:
        try:
            validate(instance=case[1], schema=case[2])

        except Exception as e:
            logger.error(e)
            return case

    return None


def initialise(dor_instance):
    global instance
    instance = dor_instance


@blueprint.route('/info', methods=['GET'])
def info():
    # export the custodian public key
    public_key = instance.export_custodian_public_key()

    # do we have a key?
    if public_key is None:
        status_code = 204  # https://restfulapi.net/http-status-204-no-content/
        reply = None
    else:
        status_code = 200  # https://restfulapi.net/http-status-200-ok/
        reply = public_key

    # create and return response
    response = jsonify(reply)
    response.status_code = status_code
    return response


@blueprint.route('/', methods=['GET'])
def search():
    # get the search tags
    search_tags = request.form.get('search_tags', None)

    # perform the search
    reply = instance.search(search_tags)

    # create and return response
    response = jsonify(reply)
    response.status_code = 200
    return response


@blueprint.route('/', methods=['POST'])
def add():
    # convert form to dict for convenience
    form = request.form.to_dict()

    try:
        # check if the request has the required parameters
        required = ['classification', 'header']
        if 'parameters' not in form or not all(r in form['parameters'] for r in required):
            response = jsonify("invalid request (missing parameters): required={} received={}".format(required, form))
            response.status_code = 400
            return response

        # get the parameters
        parameters = json.loads(form['parameters'])

        # get classification and schema
        classification = parameters['classification']
        classification_schema = {
            "type": "string",
            "enum": ["original", "derived"]
        }

        # get header and schema
        header = parameters['header']
        header_schema = {
            "type": "object",
            "properties": {
                "type": {"type": "string"},
                "format": {"type": "string"},
                "created_t": {"type": "number"},
                "created_by": {"type": "string"},
                "provenance": {"type": "object",
                               "properties": {
                                   "parents": {
                                       "type": "array",
                                       "items": {"type": "string"}
                                   },
                                   "process": {"type": "string"},
                                   "parameters": {"type": "object"}
                               },
                               "required": ["parents", "process", "parameters"],
                               "additionalProperties": False
                               }
            },
            "required": ["type", "format", "created_t", "created_by", "provenance"],
            "additionalProperties": False
        }

        # validate JSON objects
        failed = validate_json_schemas([
            ('classification', classification, classification_schema),
            ('header', header, header_schema)
        ])

        if failed is not None:
            response = jsonify(
                "invalid request (malformed parameter '{}'): instance={} schema={}".format(failed[0], failed[1],
                                                                                           failed[2]))
            response.status_code = 400
            return response

        # get the path of the data object file
        if classification == 'original':
            attachment = request.files['attachment']

            handle, path = tempfile.mkstemp()
            os.close(handle)

            attachment.save(path)

        elif classification == 'derivative':
            path = parameters['local-data-object-path']

        else:
            response = jsonify(
                "invalid request (malformed request): classification={}".format(parameters['classification']))
            response.status_code = 400
            return response

        # add the data object to the DOR
        obj_id = instance.add(path, header)

        reply = {
            "data-object-id": obj_id
        }

        response = jsonify(reply)
        response.status_code = 201
        return response

    except Exception as e:
        response = jsonify(reply)
        response.status_code = 500
        return response


@blueprint.route('/<obj_id>/header', methods=['GET'])
def get_header(obj_id):
    header = instance.get_header(obj_id)
    return jsonify(header) if header else abort(404, description="data object with id '{}' not found.".format(obj_id))


@blueprint.route('/<obj_id>/content', methods=['GET'])
def get_content(obj_id):
    # TODO: for testing purposes only
    destination_path = os.path.join("/Users/heikoaydt/Desktop/{}.content".format(obj_id))
    response = instance.get_content(obj_id, destination_path)
    return jsonify(response) if response else abort(404,
                                                    description="data object with id '{}' not found.".format(obj_id))


@blueprint.route('/<obj_id>', methods=['DELETE'])
def delete(obj_id):
    header = instance.remove(obj_id)
    return jsonify(header) if header else abort(404, description="data object with id '{}' not found.".format(obj_id))


@blueprint.route('/<obj_id>/access', methods=['POST'])
def grant_access(obj_id):
    pass


@blueprint.route('/<obj_id>/access', methods=['DELETE'])
def revoke_access(obj_id):
    pass


@blueprint.route('/<id>/access', methods=['GET'])
def lookup_access():
    pass


@blueprint.route('/<id>/transfer', methods=['PUT'])
def transfer():
    pass
