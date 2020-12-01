"""
Flask blueprint for the SaaS Data Object Repository.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import os
import json
import logging
import subprocess

from cryptography.hazmat.primitives import hashes

from flask import Blueprint, request, send_from_directory
from flask_cors import CORS

from saas.utilities.blueprint_helpers import create_signed_response, verify_request
from saas.utilities.general_helpers import dump_json_to_file
from saas.eckeypair import ECKeyPair, hash_json_object, hash_file_content
from saas.node import Node

# create the blueprint object and allows CORS for the processor route
blueprint = Blueprint('repository', __name__)
CORS(blueprint)

logger = logging.getLogger('DOR.Blueprint')
node: Node


def initialise(node_instance):
    global node
    node = node_instance


@blueprint.route('/', methods=['GET'])
def search():
    return create_signed_response(node, '/', 501, "Search is not yet implemented.")


@blueprint.route('/', methods=['POST'])
def add():
    url = "POST:/"
    body_specification = {
        'type': {
            'type': 'string',
            'enum': ['internal', 'import']
        },
        'header': {
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
        },
        'owner_public_key': {
            'type': 'string'
        }
    }

    # verify the request
    verified, status_code, message, body, files = verify_request(url, request, body_specification, ['attachment'])
    if not verified:
        return create_signed_response(node, url, status_code, message)

    # recreate ECKeyPair (public key only) of the data object owner
    owner = ECKeyPair.from_public_key_string(body['owner_public_key'])

    # add the data object to the DOR
    # obj_id = instance.add(files['attachment'], body['header'], owner)

    # calculate hashes for the data object header and content
    h_hash = hash_json_object(body['header'])
    c_hash = hash_file_content(files['attachment'])

    # calculate the data object id as a hash of the hashed data object header and content
    digest = hashes.Hash(hashes.SHA256())
    digest.update(h_hash)
    digest.update(c_hash)
    obj_id = digest.finalize()

    # convert into strings
    h_hash = h_hash.hex()
    c_hash = c_hash.hex()
    obj_id = obj_id.hex()

    # check if there is already a data object with the same id
    if node.dor.get_data_object_by_id(obj_id) is not None:
        # the data object already exists, nothing to do here.
        # TODO: decide if this is correct behaviour - in the meantime, just return the object id
        # current behaviour makes it impossible for the caller to know if a data object already existed
        # or not. question is whether this matters or not. the important point is that after calling
        # 'add' the data object is in the DOR.
        logger.warning("data object '{}' already exists. not adding to DOR.".format(obj_id))

        return create_signed_response(node, url, 200, {
            "data_object_id": obj_id
        })

    # check if there are already data objects with the same content
    if node.dor.get_data_objects_by_content_hash(c_hash):
        # it is possible for cases like this to happen. despite the exact same content, this may well be
        # a legitimate different data object. for example, different provenance has led to the exact same
        # outcome. we thus create a new data object
        logger.info("data object content '{}' already exists. not adding to DOR.".format(c_hash))

    else:
        logger.info("data object content '{}' does not exist yet. adding to DOR.".format(c_hash))

        # create a copy of the data object content
        destination_path = os.path.join(node.datastore_path, "{}.content".format(c_hash))
        subprocess.check_output(['cp', files['attachment'], destination_path])

    # create header file
    destination_path = os.path.join(node.datastore_path, "{}.header".format(obj_id))
    dump_json_to_file(body['header'], destination_path)
    logger.info("data object '{}' header stored at '{}'.".format(obj_id, destination_path))

    # insert record into db
    node.dor.add_data_object(h_hash, c_hash, obj_id, owner, node.key)
    logger.info("data object '{}' record added to database.".format(obj_id))

    return create_signed_response(node, url, 201, {
        "data_object_id": obj_id
    })


@blueprint.route('/<obj_id>', methods=['DELETE'])
def delete(obj_id):
    url = "DELETE:/{}".format(obj_id)

    # verify the request
    verified, status_code, message, body, files = verify_request(url, request)
    if not verified:
        return create_signed_response(node, url, status_code, message)

    # get the owner for the data object
    owner = node.dor.get_owner_for_object(obj_id)
    if not owner:
        return create_signed_response(node, url, 404, "Data object '{}' not found.".format(obj_id))

    # verify the the request using the owner public key
    authorisation = json.loads(request.form['authorisation'])
    if not owner.verify_authorisation_token(authorisation['signature'], url):
        return create_signed_response(node, url, 401, "Authorisation failed. Action not allowed.")

    # delete the data object
    # header = instance.remove(obj_id)

    # get the header (if it exists)
    header_path = os.path.join(node.datastore_path, "{}.header".format(obj_id))
    if not os.path.isfile(header_path):
        return create_signed_response(node, url, 404, "Data object '{}' not found.".format(obj_id))

    # read the header content
    with open(header_path, 'r') as f:
        header = json.loads(f.read())

        # remove the header file
        os.remove(header_path)

        # delete the database record
        record = node.dor.delete_data_object(obj_id)

        # check if there are still reference to this data object content (there could be more than one)
        # we only count the ones for which we are custodian
        records = []
        for record in node.dor.get_data_objects_by_content_hash(record['c_hash']):
            if record['custodian_iid'] == node.key.iid:
                records.append(record)

        # if there are no other records that refer to this data object content, then we can delete it
        if not records:
            path = os.path.join(node.datastore_path, "{}.content".format(record['c_hash']))
            os.remove(path)
            logger.info("data object content '{}' deleted.".format(record['c_hash']))

        return create_signed_response(node, url, 200, {
            "header": header
        })


@blueprint.route('/<obj_id>/header', methods=['GET'])
def get_header(obj_id):
    url = "GET:/{}/header".format(obj_id)

    # verify the request
    verified, status_code, message, body, files = verify_request(url, request)
    if not verified:
        return create_signed_response(node, url, status_code, message)

    # get the header (if it exists)
    header_path = os.path.join(node.datastore_path, "{}.header".format(obj_id))
    if not os.path.isfile(header_path):
        return create_signed_response(node, url, 404, "Data object '{}' not found.".format(obj_id))

    # read the header content
    with open(header_path, 'r') as f:
        return create_signed_response(node, url, 200, {
            "header": json.loads(f.read())
        })


@blueprint.route('/<obj_id>/content', methods=['GET'])
def get_content(obj_id):
    url = "GET:/{}/content".format(obj_id)
    # TODO: update the schema checking for the whole body not just individual items
    body_specification = {
        'type': {
            'type': 'string',
            'enum': ['export', 'internal']
        }
        # 'destination_path': {
        #     'type': 'string'
        # }
    }

    # verify the request
    verified, status_code, message, body, files = verify_request(url, request, body_specification)
    if not verified:
        return create_signed_response(node, url, status_code, message)

    # get the path to the data object content
    record = node.dor.get_data_object_by_id(obj_id)
    if not record:
        return create_signed_response(node, url, 404, "Data object '{}' not found.".format(obj_id))

    if body['type'] == 'export':
        # get the public key of the user
        authorisation = json.loads(request.form['authorisation'])
        user = ECKeyPair.from_public_key_string(authorisation['public_key'])

        # does the specified user have access rights?
        if not node.dor.has_access(obj_id, user):
            return create_signed_response(node, url, 401,
                                          "Authorisation failed. User '{}' has no permission to access data object "
                                          "'{}'.".format(user.iid, obj_id)
                                          )

        # verify the the request using the user public key
        if not user.verify_authorisation_token(authorisation['signature'], url, body):
            return create_signed_response(node, url, 401, "Authorisation failed.")

        # stream the file content
        head_tail = os.path.split(os.path.join(node.datastore_path, "{}.content".format(record['c_hash'])))
        return send_from_directory(head_tail[0], head_tail[1], as_attachment=True)

    elif body['type'] == 'internal':
        return create_signed_response(node, url, 200, {
            "path": os.path.join(node.datastore_path, "{}.content".format(record['c_hash']))
        })

    else:
        return create_signed_response(node, url, 500, "Unexpected request type '{}'.".format(body['type']))


@blueprint.route('/<obj_id>/access', methods=['POST'])
def grant_access_permission(obj_id):
    url = "POST:/{}/access".format(obj_id)
    body_specification = {
        'user_public_key': {
            'type': 'string'
        }
    }

    # verify the request
    verified, status_code, message, body, files = verify_request(url, request, body_specification)
    if not verified:
        return create_signed_response(node, url, status_code, message)

    # get the owner for the data object
    owner = node.dor.get_owner_for_object(obj_id)
    if not owner:
        return create_signed_response(node, url, 404, "Data object '{}' not found.".format(obj_id))

    # verify the the request using the owner public key
    authorisation = json.loads(request.form['authorisation'])
    if not owner.verify_authorisation_token(authorisation['signature'], url, body):
        return create_signed_response(node, url, 401, "Authorisation failed. Action not allowed.")

    # grant access permissions to the user
    user = ECKeyPair.from_public_key_string(body['user_public_key'])
    node.dor.grant_access(obj_id, user)

    return create_signed_response(node, url, 200, "Access granted.")


@blueprint.route('/<obj_id>/access', methods=['DELETE'])
def revoke_access_permission(obj_id):
    url = "DELETE:/{}/access".format(obj_id)
    body_specification = {
        'user_public_key': {
            'type': 'string'
        }
    }

    # verify the request
    verified, status_code, message, body, files = verify_request(url, request, body_specification)
    if not verified:
        return create_signed_response(node, url, status_code, message)

    # get the owner for the data object
    owner = node.dor.get_owner_for_object(obj_id)
    if not owner:
        return create_signed_response(node, url, 404, "Data object '{}' not found.".format(obj_id))

    # verify the the request using the owner public key
    authorisation = json.loads(request.form['authorisation'])
    if not owner.verify_authorisation_token(authorisation['signature'], url, body):
        return create_signed_response(node, url, 401, "Authorisation failed. Action not allowed.")

    # grant access permissions to the user
    user = ECKeyPair.from_public_key_string(body['user_public_key'])
    node.dor.revoke_access(obj_id, user)

    return create_signed_response(node, url, 200, "Access revoked.")


@blueprint.route('/<obj_id>/access', methods=['GET'])
def get_access_permissions(obj_id):
    url = "GET:/{}/access".format(obj_id)

    # verify the request
    verified, status_code, message, body, files = verify_request(url, request)
    if not verified:
        return create_signed_response(node, url, status_code, message)

    # get the header (if it exists)
    access = node.dor.get_access_permissions(obj_id)
    if not access:
        access = []

    return create_signed_response(node, url, 200, {
        "access": access
    })


@blueprint.route('/<obj_id>/owner', methods=['GET'])
def get_owner(obj_id):
    url = "GET:/{}/owner".format(obj_id)

    # verify the request
    verified, status_code, message, body, files = verify_request(url, request)
    if not verified:
        return create_signed_response(node, url, status_code, message)

    # get the header (if it exists)
    owner = node.dor.get_owner_for_object(obj_id)
    if owner:
        return create_signed_response(node, url, 200, {
            "owner_iid": owner.iid,
            "owner_public_key": owner.public_as_string()
        })
    else:
        return create_signed_response(node, url, 404, "Data object '{}' not found.".format(obj_id))


@blueprint.route('/<obj_id>/owner', methods=['PUT'])
def transfer_ownership(obj_id):
    url = "PUT:/{}/owner".format(obj_id)
    body_specification = {
        'new_owner_public_key': {
            'type': 'string'
        }
    }

    # verify the request
    verified, status_code, message, body, files = verify_request(url, request, body_specification)
    if not verified:
        return create_signed_response(node, url, status_code, message)

    # get the owner for the data object
    owner = node.dor.get_owner_for_object(obj_id)
    if not owner:
        return create_signed_response(node, url, 404, "Data object '{}' not found.".format(obj_id))

    # verify the the request using the owner public key
    authorisation = json.loads(request.form['authorisation'])
    if not owner.verify_authorisation_token(authorisation['signature'], url, body):
        return create_signed_response(node, url, 401, "Authorisation failed. Action not allowed.")

    # update owner of data object
    new_owner = ECKeyPair.from_public_key_string(body['new_owner_public_key'])
    node.dor.update_ownership(obj_id, new_owner)
    return create_signed_response(node, url, 200,
                                  "Ownership of data object '{}' transferred to '{}'.".format(obj_id, new_owner.iid))
