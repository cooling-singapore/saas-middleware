import logging
import os

from flask import Blueprint, send_from_directory, jsonify

from saas.schemas import data_object_descriptor_schema
from saas.rest.proxy import EndpointProxy
from saas.rest.request_manager import request_manager
from saas.helpers import get_timestamp_now, load_json_from_file

logger = logging.getLogger('dor.blueprint')
endpoint_prefix = "/api/v1/repository"

search_body_specification = {
    'type': 'object',
    'properties': {
        'owner_iid': {'type': 'string'},
        'patterns': {
            'type': 'array',
            'items': {'type': 'string'}
        }
    },
    'required': ['patterns']
}

add_body_specification = {
    'type': 'object',
    'properties': {
        'owner_iid': {'type': 'string'},
        'descriptor': data_object_descriptor_schema,
        'access_restricted': {'type': 'boolean'},
        'content_encrypted': {'type': 'boolean'},
        'content_key': {'type': 'string'}
    },
    'required': ['owner_iid', 'descriptor', 'access_restricted', 'content_encrypted']
}

transfer_ownership_body_specification = {
    'type': 'object',
    'properties': {
        'new_owner_iid': {'type': 'string'},
        'content_key': {'type': 'string'}
    },
    'required': ['new_owner_iid']
}

tags_body_specification = {
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

delete_tags_body_specification = {
    'type': 'array',
    'items': {
        'type': 'string'
    }
}


class DORBlueprint:
    def __init__(self, node):
        self._node = node

    def blueprint(self):
        blueprint = Blueprint('repository', __name__, url_prefix=endpoint_prefix)
        blueprint.add_url_rule('', self.search.__name__, self.search, methods=['GET'])
        blueprint.add_url_rule('', self.add.__name__, self.add, methods=['POST'])
        blueprint.add_url_rule('/<obj_id>', self.delete.__name__, self.delete, methods=['DELETE'])
        blueprint.add_url_rule('/<obj_id>/descriptor', self.get_descriptor.__name__, self.get_descriptor, methods=['GET'])
        blueprint.add_url_rule('/<obj_id>/content', self.get_content.__name__, self.get_content, methods=['GET'])
        blueprint.add_url_rule('/<obj_id>/access', self.get_access_overview.__name__, self.get_access_overview, methods=['GET'])
        blueprint.add_url_rule('/<obj_id>/access/<iid>', self.grant_access.__name__, self.grant_access, methods=['POST'])
        blueprint.add_url_rule('/<obj_id>/access/<iid>', self.revoke_access.__name__, self.revoke_access, methods=['DELETE'])
        blueprint.add_url_rule('/<obj_id>/owner', self.get_owner.__name__, self.get_owner, methods=['GET'])
        blueprint.add_url_rule('/<obj_id>/owner', self.transfer_ownership.__name__, self.transfer_ownership, methods=['PUT'])
        blueprint.add_url_rule('/<obj_id>/tags', self.get_tags.__name__, self.get_tags, methods=['GET'])
        blueprint.add_url_rule('/<obj_id>/tags', self.update_tags.__name__, self.update_tags, methods=['PUT'])
        blueprint.add_url_rule('/<obj_id>/tags', self.remove_tags.__name__, self.remove_tags, methods=['DELETE'])
        return blueprint

    @request_manager.verify_request_body(search_body_specification)
    def search(self):
        body = request_manager.get_request_variable('body')
        patterns = body['patterns']
        owner_iid = body['owner_iid'] if 'owner_iid' in body else None

        return jsonify(self._node.db.find_data_objects(patterns, owner_iid)), 200

    @request_manager.verify_request_body(add_body_specification)
    @request_manager.verify_request_files(['attachment'])
    def add(self):
        body = request_manager.get_request_variable('body')
        files = request_manager.get_request_variable('files')

        owner_iid = body['owner_iid']
        descriptor = body['descriptor']
        access_restricted = body['access_restricted']
        content_encrypted = body['content_encrypted']
        content_key = body['content_key'] if 'content_key' in body else "no-content-key"
        content_path = files['attachment']

        status, result = self._node.dor.add(owner_iid, descriptor, content_path,
                                            access_restricted, content_encrypted, content_key)
        return jsonify(result), status

    @request_manager.verify_authorisation_by_owner('obj_id')
    def delete(self, obj_id):
        status, result = self._node.dor.delete(obj_id)
        return jsonify(result), status

    def get_descriptor(self, obj_id):
        descriptor_path = self._node.dor.obj_descriptor_path(obj_id)
        if os.path.isfile(descriptor_path):
            descriptor = load_json_from_file(descriptor_path)
            return jsonify(descriptor), 200

        return jsonify(f"Data object {obj_id} not found."), 404

    @request_manager.verify_authorisation_by_owner('obj_id')
    def get_content(self, obj_id):
        # get the content hash for the data object
        record = self._node.db.get_object_by_id(obj_id)
        if not record:
            return jsonify(f"Data object '{obj_id}' not found."), 404

        # stream the file content
        head, tail = os.path.split(self._node.dor.obj_content_path(record.c_hash))
        return send_from_directory(head, tail, as_attachment=True)

    def get_access_overview(self, obj_id):
        if not self._node.db.get_object_by_id(obj_id):
            return jsonify(f"{obj_id} not found"), 404

        else:
            return jsonify(
                self._node.db.get_access_list(obj_id)
            ), 200

    @request_manager.verify_authorisation_by_owner('obj_id')
    def grant_access(self, obj_id, iid):
        if not self._node.db.get_object_by_id(obj_id):
            return jsonify(f"data object (id={obj_id}) not found"), 404

        identity = self._node.db.get_identity(iid)
        if identity is None:
            return jsonify(f"identity (iid={iid}) not found"), 404

        return jsonify({
            obj_id: self._node.db.grant_access(obj_id, identity)
        }), 200

    @request_manager.verify_authorisation_by_owner('obj_id')
    def revoke_access(self, obj_id, iid):
        if not self._node.db.get_object_by_id(obj_id):
            return jsonify(f"data object (id={obj_id}) not found"), 404

        identity = self._node.db.get_identity(iid)
        if identity is None:
            return jsonify(f"identity (iid={iid}) not found"), 404

        return jsonify({
            obj_id: self._node.db.revoke_access(obj_id, identity)
        }), 200

    def get_owner(self, obj_id):
        owner = self._node.db.get_owner(obj_id)
        if owner:
            return jsonify({
                "obj_id": obj_id,
                "owner_iid": owner.id()
            }), 200
        else:
            return jsonify(f"Data object '{obj_id}' not found."), 404

    @request_manager.verify_request_body(transfer_ownership_body_specification)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def transfer_ownership(self, obj_id):
        # get the record for this data object
        record = self._node.db.get_object_by_id(obj_id)
        if record is None:
            return jsonify(f"Data object '{obj_id}' not found."), 404

        body = request_manager.get_request_variable('body')
        new_owner = self._node.db.get_identity(body['new_owner_iid'])
        if new_owner is None:
            return jsonify(f"New owner identity (iid='{body['new_owner_iid']}') not found."), 404

        content_key = body['content_key'] if 'content_key' in body else None

        self._node.db.update_ownership(obj_id, new_owner, content_key)

        # retrieve the owner of the data object
        owner = self._node.db.get_owner(obj_id)
        return jsonify({obj_id: owner.id()}), 200

    def get_tags(self, obj_id):
        return jsonify(self._node.db.get_tags(obj_id)), 200

    @request_manager.verify_request_body(tags_body_specification)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def update_tags(self, obj_id):
        body = request_manager.get_request_variable('body')
        self._node.db.update_tags(obj_id, body)

        return jsonify(self._node.db.get_tags(obj_id)), 200

    @request_manager.verify_request_body(delete_tags_body_specification)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def remove_tags(self, obj_id):
        body = request_manager.get_request_variable('body')
        self._node.db.remove_tags(obj_id, body)

        return jsonify(self._node.db.get_tags(obj_id)), 200


class DORProxy(EndpointProxy):
    def __init__(self, remote_address):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address)

    def search(self, patterns, owner_iid=None):
        body = {
            'patterns': patterns,
        }

        if owner_iid is not None:
            body['owner_iid'] = owner_iid

        code, r = self.get('', body=body)
        return r

    def add_data_object(self, content_path, owner, access_restricted, content_encrypted, content_key,
                        data_type, data_format, created_by, created_t=None, recipe=None):
        body = {
            'owner_iid': owner.id(),
            'descriptor': {
                'data_type': data_type,
                'data_format': data_format,
                'created_t': created_t if created_t else get_timestamp_now(),
                'created_by': created_by
            },
            'access_restricted': access_restricted,
            'content_encrypted': content_encrypted
        }

        if content_key is not None:
            body['content_key'] = content_key

        if recipe is not None:
            body['descriptor']['recipe'] = recipe

        code, r = self.post('', body=body, attachment=content_path)
        return (r['data_object_id'], r['descriptor']) if 'data_object_id' in r else None

    def delete_data_object(self, obj_id, authorisation_key):
        code, r = self.delete(f"/{obj_id}", with_authorisation_by=authorisation_key)
        return r if code == 200 else None

    def get_descriptor(self, obj_id):
        code, r = self.get(f"/{obj_id}/descriptor")
        return r if code == 200 else None

    def get_content(self, obj_id, authorisation_key, download_path):
        code, r = self.get(f"/{obj_id}/content", download_path=download_path, with_authorisation_by=authorisation_key)
        return download_path if code == 200 else None

    def get_access_overview(self, obj_id):
        code, r = self.get(f"/{obj_id}/access")
        return r

    def grant_access(self, obj_id, authorisation_key, identity):
        code, r = self.post(f"/{obj_id}/access/{identity.id()}", with_authorisation_by=authorisation_key)
        return r

    def revoke_access(self, obj_id, authorisation_key, identity):
        code, r = self.delete(f"/{obj_id}/access/{identity.id()}", with_authorisation_by=authorisation_key)
        return r

    def get_owner(self, obj_id):
        code, r = self.get(f"/{obj_id}/owner")
        return r

    def transfer_ownership(self, obj_id, authorisation_key, new_owner, content_key=None):
        body = {
            'new_owner_iid': new_owner.id()
        }

        if content_key is not None:
            body['content_key'] = content_key

        code, r = self.put(f"/{obj_id}/owner", body, with_authorisation_by=authorisation_key)
        return r if code == 200 else None

    def get_tags(self, obj_id):
        code, r = self.get(f"/{obj_id}/tags")
        return r

    def update_tags(self, obj_id, authorisation_key, tags):
        body = []
        for key, value in tags.items():
            body.append({
                'key': key,
                'value': value
            })

        code, r = self.put(f"/{obj_id}/tags", body=body, with_authorisation_by=authorisation_key)
        return r

    def remove_tags(self, obj_id, authorisation_key, keys):
        code, r = self.delete(f"/{obj_id}/tags", body=keys, with_authorisation_by=authorisation_key)
        return r
