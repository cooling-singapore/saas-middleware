import logging
import os

from flask import Blueprint, request, send_from_directory, jsonify
from flask_cors import CORS

from saas.schemas import data_object_descriptor_schema, processor_descriptor_schema
from saas.rest.proxy import EndpointProxy
from saas.utilities.blueprint_helpers import request_manager
from saas.utilities.general_helpers import get_timestamp_now

logger = logging.getLogger('dor.blueprint')
endpoint_prefix = "/api/v1/repository"

security_specification = {
    'type': 'object',
    'properties': {
        'access_restricted': {'type': 'boolean'},
        'content_encrypted': {'type': 'boolean'}
    },
    'required': ['access_restricted', 'content_encrypted']
}

data_body_specification = {
    'type': 'object',
    'properties': {
        'type': {'type': 'string', 'enum': ['data_object', 'processor']},
        'security': security_specification,
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
    'required': ['type', 'security', 'owner_public_key', 'descriptor']
}

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


class DORBlueprint:
    def __init__(self, node):
        self._node = node

    def blueprint(self):
        # create the blueprint and allow CORS for the processor route
        blueprint = Blueprint('repository', __name__, url_prefix=endpoint_prefix)
        blueprint.add_url_rule('', self.search.__name__, self.search, methods=['GET'])
        blueprint.add_url_rule('', self.add.__name__, self.add, methods=['POST'])
        blueprint.add_url_rule('/<obj_id>', self.delete.__name__, self.delete, methods=['DELETE'])
        blueprint.add_url_rule('/<obj_id>/descriptor', self.get_descriptor.__name__, self.get_descriptor, methods=['GET'])
        blueprint.add_url_rule('/<obj_id>/content', self.get_content.__name__, self.get_content, methods=['GET'])
        blueprint.add_url_rule('/<obj_id>/access', self.get_access.__name__, self.get_access, methods=['GET'])
        blueprint.add_url_rule('/<obj_id>/access', self.grant_access.__name__, self.grant_access, methods=['POST'])
        blueprint.add_url_rule('/<obj_id>/access', self.revoke_access.__name__, self.revoke_access, methods=['DELETE'])
        blueprint.add_url_rule('/<obj_id>/owner', self.get_owner.__name__, self.get_owner, methods=['GET'])
        blueprint.add_url_rule('/<obj_id>/owner', self.transfer_ownership.__name__, self.transfer_ownership, methods=['PUT'])
        blueprint.add_url_rule('/<obj_id>/tags', self.get_tags.__name__, self.get_tags, methods=['GET'])
        blueprint.add_url_rule('/<obj_id>/tags', self.update_tags.__name__, self.update_tags, methods=['PUT'])
        blueprint.add_url_rule('/<obj_id>/tags', self.remove_tags.__name__, self.remove_tags, methods=['DELETE'])

        CORS(blueprint)
        return blueprint

    @request_manager.authentication_required
    def search(self):
        key_criterion = request.args.get('key_criterion')
        value_criterion = request.args.get('value_criterion')

        return jsonify({
            "objects": self._node.db.find_data_objects(key_criterion, value_criterion)
        }), 200

    @request_manager.authentication_required
    @request_manager.verify_request_body(data_body_specification)
    @request_manager.verify_request_files(['attachment'])
    def add(self):
        body = request_manager.get_request_variable('body')
        files = request_manager.get_request_variable('files')

        status, result = self._node.dor.add(body['owner_public_key'], body['security'],
                                            body['descriptor'], files['attachment'])
        return jsonify(result), status

    @request_manager.authentication_required
    @request_manager.verify_authorisation_by_owner('obj_id')
    def delete(self, obj_id):
        status, result = self._node.dor.delete(obj_id)
        return jsonify(result), status

    @request_manager.authentication_required
    def get_descriptor(self, obj_id):
        status, result = self._node.dor.get_descriptor(obj_id)
        return jsonify(result), status

    @request_manager.authentication_required
    @request_manager.verify_authorisation_by_owner('obj_id')
    def get_content(self, obj_id):
        # get the content hash for the data object
        record = self._node.db.get_object_by_id(obj_id)
        if not record:
            return jsonify(f"Data object '{obj_id}' not found."), 404

        # stream the file content
        head, tail = os.path.split(self._node.dor.obj_content_path(record.c_hash))
        return send_from_directory(head, tail, as_attachment=True)

    @request_manager.authentication_required
    def get_access(self, obj_id):
        return jsonify({
            "access": self._node.db.get_access_list(obj_id)
        }), 200

    @request_manager.authentication_required
    @request_manager.verify_request_body(grant_access_body_specification)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def grant_access(self, obj_id):
        body = request_manager.get_request_variable('body')
        self._node.db.grant_access(obj_id, body['public_key'], body['permission'])

        return jsonify("Access granted."), 200

    @request_manager.authentication_required
    @request_manager.verify_request_body(revoke_access_body_specification)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def revoke_access(self, obj_id):
        body = request_manager.get_request_variable('body')
        self._node.db.revoke_access(obj_id, body['public_key'])

        return jsonify("Access revoked."), 200

    @request_manager.authentication_required
    def get_owner(self, obj_id):
        owner = self._node.db.get_owner(obj_id)
        if owner:
            return jsonify({
                "owner_iid": owner.iid,
                "owner_public_key": owner.public_as_string()
            }), 200
        else:
            return jsonify(f"Data object '{obj_id}' not found."), 404

    @request_manager.authentication_required
    @request_manager.verify_request_body(owner_key_body_specification)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def transfer_ownership(self, obj_id):
        body = request_manager.get_request_variable('body')
        self._node.db.update_ownership(obj_id, body['new_owner_public_key'])

        return jsonify(f"Ownership of data object '{obj_id}' transferred to '{body['new_owner_public_key']}'."), 200

    @request_manager.authentication_required
    def get_tags(self, obj_id):
        return jsonify({
            "tags": self._node.db.get_tags(obj_id)
        }), 200

    @request_manager.authentication_required
    @request_manager.verify_request_body(tags_body_specification)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def update_tags(self, obj_id):
        body = request_manager.get_request_variable('body')
        self._node.db.update_tags(obj_id, body['tags'])

        return jsonify("Tags updated."), 200

    @request_manager.authentication_required
    @request_manager.verify_request_body(delete_tags_body_specification)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def remove_tags(self, obj_id):
        body = request_manager.get_request_variable('body')
        self._node.db.remove_tags(obj_id, body['keys'])

        return jsonify("Tags updated."), 200


class DORProxy(EndpointProxy):
    def __init__(self, remote_address, sender):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address, sender)

    def search_by_tags(self, key_criterion=None, value_criterion=None):
        parameters = []
        if key_criterion:
            parameters.append(('key_criterion', key_criterion))
        if value_criterion:
            parameters.append(('value_criterion', value_criterion))

        r = self.get("", parameters=parameters)
        return r['reply']['objects']

    def create_recipe(self, task_descriptor, output_name):
        return {
            'task_descriptor': task_descriptor,
            'output_name': output_name
        }

    def add_data_object(self, content_path, owner, access_restricted, content_encrypted,
                        data_type, data_format, created_by, created_t=None, recipe=None):
        body = {
            'type': 'data_object',
            'owner_public_key': owner.public_as_string(),
            'security': {
                'access_restricted': access_restricted,
                'content_encrypted': content_encrypted
            },
            'descriptor': {
                'data_type': data_type,
                'data_format': data_format,
                'created_t': created_t if created_t else get_timestamp_now(),
                'created_by': created_by
            }
        }

        if recipe is not None:
            body['descriptor']['recipe'] = recipe

        r = self.post('', body=body, attachment=content_path)
        return (r['reply']['data_object_id'], r['reply']['descriptor']) if 'data_object_id' in r['reply'] else None

    def add_processor(self, content_path, owner, descriptor):
        body = {
            'type': 'processor',
            'owner_public_key': owner.public_as_string(),
            'descriptor': descriptor
        }

        r = self.post('', body=body, attachment=content_path)
        return r['reply']['data_object_id'] if 'data_object_id' in r['reply'] else None

    def delete_data_object(self, obj_id, owner):
        r = self.delete(f"/{obj_id}", with_authorisation_by=owner)
        return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None

    def get_descriptor(self, obj_id):
        r = self.get(f"/{obj_id}/descriptor")
        return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None

    def get_content(self, obj_id, owner, download_path):
        r = self.get(f"/{obj_id}/content", download_path=download_path, with_authorisation_by=owner)
        return r

    def get_access_permissions(self, obj_id):
        r = self.get(f"/{obj_id}/access")
        return r['reply']['access'] if 'access' in r['reply'] else None

    def grant_access(self, obj_id, owner, key, permission=""):
        body = {
            'public_key': key.public_as_string(),
            'permission': permission
        }

        r = self.post(f"/{obj_id}/access", body=body, with_authorisation_by=owner)
        return r['reply']

    def revoke_access(self, obj_id, owner, key):
        body = {
            'public_key': key.public_as_string()
        }

        r = self.delete(f"/{obj_id}/access", body=body, with_authorisation_by=owner)
        return r['reply']

    def get_owner(self, obj_id):
        r = self.get(f"/{obj_id}/owner")
        return r['reply']

    def transfer_ownership(self, obj_id, current_owner, new_owner):
        body = {
            'new_owner_public_key': new_owner.public_as_string()
        }

        r = self.put(f"/{obj_id}/owner", body, with_authorisation_by=current_owner)
        return r['reply']

    def get_tags(self, obj_id):
        r = self.get(f"/{obj_id}/tags")
        return r['reply']['tags']

    def update_tags(self, obj_id, owner, tags):
        body = {'tags': []}
        for key in tags:
            value = tags[key]

            body['tags'].append({
                'key': key,
                'value': value
            })

        r = self.put(f"/{obj_id}/tags", body=body, with_authorisation_by=owner)
        return r['reply']

    def remove_tags(self, obj_id, owner, keys):
        body = {
            'keys': keys
        }

        r = self.delete(f"/{obj_id}/tags", body=body, with_authorisation_by=owner)
        return r['reply']

