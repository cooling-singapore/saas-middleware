"""
Flask blueprint for the SaaS Data Object Repository.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging
import os

from flask import Blueprint, request, send_from_directory, jsonify
from flask_cors import CORS

from saas.json_schemas import data_object_descriptor_schema, processor_descriptor_schema
from saas.utilities.blueprint_helpers import request_manager
from saas.cryptography.eckeypair import ECKeyPair
from saas.node import Node

# create the blueprint object and allows CORS for the processor route
blueprint = Blueprint('repository', __name__)
CORS(blueprint)

logger = logging.getLogger('DOR.Blueprint')
node: Node


def initialise(node_instance):
    global node
    node = node_instance


data_body_specification = {
    'type': 'object',
    'properties': {
        'type': {'type': 'string', 'enum': ['data_object', 'processor']},
        'owner_public_key': {'type': 'string'}
    },
    'if': {
        'properties': {'type': {'const': 'data_object'}}
    },
    'then': {
        'properties': {
            'descriptor': data_object_descriptor_schema
        }
    },
    'else': {
        'properties': {
            'descriptor': processor_descriptor_schema
        }
    },
    'required': ['type', 'owner_public_key', 'descriptor']
}


@blueprint.route('', methods=['POST'])
@request_manager.authentication_required
@request_manager.verify_request_body(data_body_specification)
@request_manager.verify_request_files(['attachment'])
def add():
    body = request_manager.get_request_variable('body')
    files = request_manager.get_request_variable('files')

    status, result = node.dor.add(body['owner_public_key'], body['descriptor'], files['attachment'])
    return jsonify(result), status


@blueprint.route('/<obj_id>', methods=['DELETE'])
@request_manager.authentication_required
@request_manager.verify_authorisation_by_owner('obj_id')
def delete(obj_id):
    status, result = node.dor.delete(obj_id)
    return jsonify(result), status


@blueprint.route('/<obj_id>', methods=['GET'])
@blueprint.route('/<obj_id>/descriptor', methods=['GET'])
@request_manager.authentication_required
def get_descriptor(obj_id):
    status, result = node.dor.get_descriptor(obj_id)
    return jsonify(result), status


@blueprint.route('/<obj_id>/content', methods=['GET'])
@request_manager.authentication_required
@request_manager.verify_authorisation_by_owner('obj_id')
def get_content(obj_id):
    # get the content hash for the data object
    record = node.db.get_object_by_id(obj_id)
    if not record:
        return jsonify(f"Data object '{obj_id}' not found."), 404

    # stream the file content
    head, tail = os.path.split(node.dor.obj_content_path(record.c_hash))
    return send_from_directory(head, tail, as_attachment=True)


grant_access_body_specification = {
    'type': 'object',
    'properties': {
        'public_key': {'type': 'string'},
        'permission': {'type': 'string'}
    },
    'required': ['public_key', 'permission']
}

revoke_access_body_specification = {
    'type': 'object',
    'properties': {
        'public_key': {'type': 'string'}
    },
    'required': ['public_key']
}

owner_key_body_specification = {
    'new_owner_public_key': {
        'type': 'string'
    }
}


@blueprint.route('/<obj_id>/access', methods=['GET'])
@request_manager.authentication_required
def get_access_permissions(obj_id):
    return jsonify({
        "access": node.db.get_access_list(obj_id)
    }), 200


@blueprint.route('/<obj_id>/access', methods=['POST'])
@request_manager.authentication_required
@request_manager.verify_request_body(grant_access_body_specification)
@request_manager.verify_authorisation_by_owner('obj_id')
def grant_access(obj_id):
    body = request_manager.get_request_variable('body')
    node.db.grant_access(obj_id, body['public_key'], body['permission'])

    return jsonify("Access granted."), 200


@blueprint.route('/<obj_id>/access', methods=['DELETE'])
@request_manager.authentication_required
@request_manager.verify_request_body(revoke_access_body_specification)
@request_manager.verify_authorisation_by_owner('obj_id')
def revoke_access(obj_id):
    body = request_manager.get_request_variable('body')
    node.db.revoke_access(obj_id, body['public_key'])

    return jsonify("Access revoked."), 200


@blueprint.route('/<obj_id>/owner', methods=['GET'])
@request_manager.authentication_required
def get_owner(obj_id):
    owner = node.db.get_owner(obj_id)
    if owner:
        return jsonify({
            "owner_iid": owner.iid,
            "owner_public_key": owner.public_as_string()
        }), 200
    else:
        return jsonify(f"Data object '{obj_id}' not found."), 404


@blueprint.route('/<obj_id>/owner', methods=['PUT'])
@request_manager.authentication_required
@request_manager.verify_request_body(owner_key_body_specification)
@request_manager.verify_authorisation_by_owner('obj_id')
def transfer_ownership(obj_id):
    body = request_manager.get_request_variable('body')
    node.db.update_ownership(obj_id, body['new_owner_public_key'])

    return jsonify(f"Ownership of data object '{obj_id}' transferred to '{body['new_owner_public_key']}'."), 200


tags_body_specification = {
    'tags': {
        'type': 'array',
        'items': {
            'type': 'object',
            'properties': {
                'key': {'type': 'string'},
                'value': {'type': 'string'}
            },
            'required': ['key', 'value']
        }
    }
}

delete_tags_body_specification = {
    'keys': {
        'type': 'array',
        'items': {
            'type': 'string'
        }
    }
}


@blueprint.route('', methods=['GET'])
@request_manager.authentication_required
def search_by_tags():
    key_criterion = request.args.get('key_criterion')
    value_criterion = request.args.get('value_criterion')

    return jsonify({
        "objects": node.db.find_data_objects(key_criterion, value_criterion)
    }), 200


@blueprint.route('/<obj_id>/tags', methods=['GET'])
@request_manager.authentication_required
def get_tags(obj_id):
    return jsonify({
        "tags": node.db.get_tags(obj_id)
    }), 200


@blueprint.route('/<obj_id>/tags', methods=['PUT'])
@request_manager.authentication_required
@request_manager.verify_request_body(tags_body_specification)
@request_manager.verify_authorisation_by_owner('obj_id')
def update_tags(obj_id):
    body = request_manager.get_request_variable('body')
    node.db.update_tags(obj_id, body['tags'])

    return jsonify("Tags updated."), 200


@blueprint.route('/<obj_id>/tags', methods=['DELETE'])
@request_manager.authentication_required
@request_manager.verify_request_body(delete_tags_body_specification)
@request_manager.verify_authorisation_by_owner('obj_id')
def remove_tags(obj_id):
    body = request_manager.get_request_variable('body')
    node.db.remove_tags(obj_id, body['keys'])

    return jsonify("Tags updated."), 200
