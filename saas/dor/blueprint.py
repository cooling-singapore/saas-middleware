"""
Flask blueprint for the SaaS Data Object Repository.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging
import os

from flask import Blueprint, request, send_from_directory
from flask_cors import CORS

from saas.json_schemas import data_object_descriptor_schema, processor_descriptor_schema
from saas.utilities.blueprint_helpers import create_signed_response
from saas.utilities.blueprint_helpers import verify_request_authentication, verify_request_body, verify_request_files
from saas.utilities.blueprint_helpers import verify_authorisation_by_owner, verify_authorisation_by_user, RequestError
from saas.eckeypair import ECKeyPair
from saas.node import Node

# create the blueprint object and allows CORS for the processor route
blueprint = Blueprint('repository', __name__)
CORS(blueprint)

logger = logging.getLogger('DOR.Blueprint')
node: Node


def initialise(node_instance):
    global node
    node = node_instance


@blueprint.route('/', methods=['POST'])
def add():
    url = "POST:/repository"
    body_specification = {
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

    try:
        # verification of authentication: required
        body, files = verify_request_authentication(url, request)

        # verification of contents: body and files
        verify_request_body(body, body_specification)
        verify_request_files(files, ['attachment'])

        # verification of authorisation: not required

        status, result = node.dor.add(body['owner_public_key'], body['descriptor'], files['attachment'])
        return create_signed_response(node, url, status, result)

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<obj_id>', methods=['DELETE'])
def delete(obj_id):
    url = f"DELETE:/repository/{obj_id}"

    try:
        # verification of authentication: required
        verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: required from owner of data object
        verify_authorisation_by_owner(request, obj_id, node, url)

        status, result = node.dor.delete(obj_id)
        return create_signed_response(node, url, status, result)

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<obj_id>', methods=['GET'])
@blueprint.route('/<obj_id>/descriptor', methods=['GET'])
def get_descriptor(obj_id):
    url = f"GET:/repository/{obj_id}/descriptor"
    logger.info(f"url={url}")
    try:
        # verification of authentication: required
        verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: not required

        status, result = node.dor.get_descriptor(obj_id)
        return create_signed_response(node, url, status, result)

    except RequestError as e:
        logger.info(f"exception: {e}")
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<obj_id>/content', methods=['GET'])
def get_content(obj_id):
    url = f"GET:/repository/{obj_id}/content"

    try:
        # verification of authentication: required
        verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: required from any user that has access permission
        verify_authorisation_by_user(request, obj_id, node, url)

        # get the content hash for the data object
        c_hash = node.dor.get_content_hash(obj_id)
        if not c_hash:
            return create_signed_response(node, url, 500, f"Content '{c_hash}' for data object '{obj_id}' not found.")

        # stream the file content
        head, tail = os.path.split(node.dor.obj_content_path(c_hash))
        return send_from_directory(head, tail, as_attachment=True)

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<obj_id>/access', methods=['GET'])
def get_access_permissions(obj_id):
    url = f"GET:/repository/{obj_id}/access"

    try:
        # verification of authentication: required
        verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: not required

        return create_signed_response(node, url, 200, {
            "access": node.dor.get_access_permissions(obj_id)
        })

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<obj_id>/access', methods=['POST'])
def grant_access(obj_id):
    url = f"POST:/repository/{obj_id}/access"
    body_specification = {
        'user_public_key': {
            'type': 'string'
        }
    }

    try:
        # verification of authentication: required
        body, files = verify_request_authentication(url, request)

        # verification of contents: body only
        verify_request_body(body, body_specification)

        # verification of authorisation: required from owner of data object
        verify_authorisation_by_owner(request, obj_id, node, url, body)

        # grant access permissions to the user
        user = ECKeyPair.from_public_key_string(body['user_public_key'])
        node.dor.grant_access(obj_id, user)

        return create_signed_response(node, url, 200, "Access granted.")

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<obj_id>/access', methods=['DELETE'])
def revoke_access(obj_id):
    url = f"DELETE:/repository/{obj_id}/access"
    body_specification = {
        'user_public_key': {
            'type': 'string'
        }
    }

    try:
        # verification of authentication: required
        body, files = verify_request_authentication(url, request)

        # verification of contents: body only
        verify_request_body(body, body_specification)

        # verification of authorisation: required from owner of data object
        verify_authorisation_by_owner(request, obj_id, node, url, body)

        # revoke access permissions from the user
        user = ECKeyPair.from_public_key_string(body['user_public_key'])
        node.dor.revoke_access(obj_id, user)

        return create_signed_response(node, url, 200, "Access revoked.")

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<obj_id>/owner', methods=['GET'])
def get_owner(obj_id):
    url = f"GET:/repository/{obj_id}/owner"

    try:
        # verification of authentication: required
        verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: not required

        # return owner information
        owner = node.dor.get_owner(obj_id)
        if owner:
            return create_signed_response(node, url, 200, {
                "owner_iid": owner.iid,
                "owner_public_key": owner.public_as_string()
            })
        else:
            return create_signed_response(node, url, 404, f"Data object '{obj_id}' not found.")

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<obj_id>/owner', methods=['PUT'])
def transfer_ownership(obj_id):
    url = f"PUT:/repository/{obj_id}/owner"
    body_specification = {
        'new_owner_public_key': {
            'type': 'string'
        }
    }

    try:
        # verification of authentication: required
        body, files = verify_request_authentication(url, request)

        # verification of contents: body only
        verify_request_body(body, body_specification)

        # verification of authorisation: required from owner of data object
        verify_authorisation_by_owner(request, obj_id, node, url, body)

        # transfer ownership
        new_owner = ECKeyPair.from_public_key_string(body['new_owner_public_key'])
        node.dor.update_ownership(obj_id, new_owner)
        return create_signed_response(node, url, 200,
                                      f"Ownership of data object '{obj_id}' transferred to '{new_owner.iid}'.")

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/', methods=['GET'])
def search_by_tags():
    url = f"GET:/repository/"

    key_criterion = request.args['key_criterion']
    value_criterion = request.args['value_criterion'] if 'value_criterion' in request.args else None

    url = f"{url}?key_criterion={key_criterion}"
    if value_criterion:
        url = f"{url}&value_criterion={value_criterion}"

    try:
        # verification of authentication: required
        body, files = verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: not required

        return create_signed_response(node, url, 200, {
            "objects": node.dor.search_by_tags(key_criterion, value_criterion)
        })

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<obj_id>/tags', methods=['GET'])
def get_tags(obj_id):
    url = f"GET:/repository/{obj_id}/tags"

    try:
        # verification of authentication: required
        body, files = verify_request_authentication(url, request)

        # verification of contents: not required

        # verification of authorisation: not required

        return create_signed_response(node, url, 200, {
            "tags": node.dor.get_tags(obj_id)
        })

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<obj_id>/tags', methods=['PUT'])
def update_tags(obj_id):
    url = f"PUT:/repository/{obj_id}/tags"
    body_specification = {
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

    try:
        # verification of authentication: required
        body, files = verify_request_authentication(url, request)

        # verification of contents: body only
        verify_request_body(body, body_specification)

        # verification of authorisation: required from owner of data object
        verify_authorisation_by_owner(request, obj_id, node, url, body)

        # grant access permissions to the user
        node.dor.update_tags(obj_id, body['tags'])

        return create_signed_response(node, url, 200, "Tags updated.")

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)


@blueprint.route('/<obj_id>/tags', methods=['DELETE'])
def remove_tags(obj_id):
    url = f"DELETE:/repository/{obj_id}/tags"
    body_specification = {
        'tags': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'key': {'type': 'string'}
                },
                'required': ['key']
            }
        }
    }

    try:
        # verification of authentication: required
        body, files = verify_request_authentication(url, request)

        # verification of contents: body only
        verify_request_body(body, body_specification)

        # verification of authorisation: required from owner of data object
        verify_authorisation_by_owner(request, obj_id, node, url, body)

        # grant access permissions to the user
        node.dor.remove_tags(obj_id, body['tags'])

        return create_signed_response(node, url, 200, "Tags updated.")

    except RequestError as e:
        return create_signed_response(node, url, e.code, e.message)
