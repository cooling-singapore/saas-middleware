import logging
import os

from flask import Response

from saas.dor.exceptions import DataObjectDescriptorNotFoundError, DataObjectNotFoundError, \
    DataObjectContentNotFoundError, OwnerIdentityNotFoundError, IdentityNotFoundError
from saas.keystore.identity import Identity
from saas.keystore.keystore import Keystore
from saas.rest.blueprint import SaaSBlueprint, create_ok_response, create_ok_attachment
from saas.schemas import data_object_descriptor_schema, git_proc_pointer_schema
from saas.rest.proxy import EndpointProxy
from saas.rest.request_manager import request_manager
from saas.helpers import get_timestamp_now, read_json_from_file

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
    }
}

add_body_specification = {
    'type': 'object',
    'properties': {
        'owner_iid': {'type': 'string'},
        'descriptor': data_object_descriptor_schema,
        'access_restricted': {'type': 'boolean'},
        'content_encrypted': {'type': 'boolean'}
    },
    'required': ['owner_iid', 'descriptor', 'access_restricted', 'content_encrypted']
}

add_gpp_body_specification = {
    'type': 'object',
    'properties': {
        'owner_iid': {'type': 'string'},
        'descriptor': data_object_descriptor_schema,
        'gpp': git_proc_pointer_schema,
        'credentials': {'type': 'object'}
    },
    'required': ['owner_iid', 'descriptor', 'gpp']
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

tags_response_schema = {
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

owner_response_schema = {
    'type': 'object',
    'properties': {
        'obj_id': {'type': 'string'},
        'owner_iid': {'type': 'string'}
    },
    'required': ['obj_id', 'owner_iid']
}

access_response_schema = {
    'type': 'array',
    'items': {'type': 'string'}
}

obj_response_schema = {
    'type': 'object',
    'properties': {
        'obj_id': {'type': 'string'},
        'descriptor': data_object_descriptor_schema
    },
    'required': ['obj_id', 'descriptor']
}

search_response_schema = {
    'type': 'array',
    'items': {
        'type': 'object',
        'properties': {
            'obj_id': {'type': 'string'},
            'tags': tags_response_schema
        },
        'required': ['obj_id', 'tags']
    }
}


class DORBlueprint(SaaSBlueprint):
    def __init__(self, node):
        super().__init__('repository', __name__, endpoint_prefix)
        self._node = node

        self.add_rule('', self.search, ['GET'], response_schema=search_response_schema)
        self.add_rule('add', self.add, ['POST'], response_schema=obj_response_schema)
        self.add_rule('add-gpp', self.add_gpp, ['POST'], response_schema=obj_response_schema)
        self.add_rule('<obj_id>', self.delete, ['DELETE'], response_schema=obj_response_schema)
        self.add_rule('<obj_id>/descriptor', self.get_descriptor, ['GET'], response_schema=obj_response_schema)
        self.add_rule('<obj_id>/content', self.get_content, ['GET'])
        self.add_rule('<obj_id>/access', self.get_access_overview, ['GET'], response_schema=access_response_schema)
        self.add_rule('<obj_id>/access/<iid>', self.grant_access, ['POST'], response_schema=access_response_schema)
        self.add_rule('<obj_id>/access/<iid>', self.revoke_access, ['DELETE'], response_schema=access_response_schema)
        self.add_rule('<obj_id>/owner', self.get_owner, ['GET'], response_schema=owner_response_schema)
        self.add_rule('<obj_id>/owner', self.transfer_ownership, ['PUT'], response_schema=owner_response_schema)
        self.add_rule('<obj_id>/tags', self.get_tags, ['GET'], response_schema=tags_response_schema)
        self.add_rule('<obj_id>/tags', self.update_tags, ['PUT'], response_schema=tags_response_schema)
        self.add_rule('<obj_id>/tags', self.remove_tags, ['DELETE'], response_schema=tags_response_schema)

    @request_manager.require_dor()
    @request_manager.verify_request_body(search_body_specification)
    def search(self) -> (Response, int):
        body = request_manager.get_request_variable('body')
        patterns = body['patterns'] if 'patterns' in body else None
        owner_iid = body['owner_iid'] if 'owner_iid' in body else None
        return create_ok_response(self._node.db.find_data_objects(patterns, owner_iid))

    @request_manager.require_dor()
    @request_manager.verify_request_body(add_body_specification)
    @request_manager.verify_request_files(['attachment'])
    def add(self) -> (Response, int):
        body = request_manager.get_request_variable('body')
        files = request_manager.get_request_variable('files')

        owner_iid = body['owner_iid']
        descriptor = body['descriptor']
        access_restricted = body['access_restricted']
        content_encrypted = body['content_encrypted']
        content_path = files['attachment']

        return create_ok_response(self._node.dor.add(owner_iid, descriptor, content_path, access_restricted,
                                                     content_encrypted))

    @request_manager.require_dor()
    @request_manager.verify_request_body(add_gpp_body_specification)
    def add_gpp(self) -> (Response, int):
        body = request_manager.get_request_variable('body')

        owner_iid = body['owner_iid']
        descriptor = body['descriptor']
        gpp = body['gpp']

        return create_ok_response(self._node.dor.add_gpp(owner_iid, descriptor, gpp))

    @request_manager.require_dor()
    @request_manager.verify_authorisation_by_owner('obj_id')
    def delete(self, obj_id: str) -> (Response, int):
        return create_ok_response(self._node.dor.delete(obj_id))

    @request_manager.require_dor()
    def get_descriptor(self, obj_id: str) -> (Response, int):
        # do we have this data object?
        if not self._node.db.get_object_by_id(obj_id):
            raise DataObjectNotFoundError(obj_id)

        descriptor_path = self._node.dor.obj_descriptor_path(obj_id)
        if not os.path.isfile(descriptor_path):
            raise DataObjectDescriptorNotFoundError(descriptor_path)

        return create_ok_response({
            'obj_id': obj_id,
            'descriptor': read_json_from_file(descriptor_path)
        })

    @request_manager.require_dor()
    @request_manager.verify_authorisation_by_owner('obj_id')
    def get_content(self, obj_id: str) -> (Response, int):
        # do we have this data object?
        record = self._node.db.get_object_by_id(obj_id)
        if not record:
            raise DataObjectNotFoundError(obj_id)

        content_path = self._node.dor.obj_content_path(record['c_hash'])
        if not os.path.isfile(content_path):
            raise DataObjectContentNotFoundError({
                'path': content_path
            })

        return create_ok_attachment(content_path)

    @request_manager.require_dor()
    def get_access_overview(self, obj_id: str) -> (Response, int):
        # do we have this data object?
        if not self._node.db.get_object_by_id(obj_id):
            raise DataObjectNotFoundError(obj_id)

        return create_ok_response(self._node.db.get_access_list(obj_id))

    @request_manager.require_dor()
    @request_manager.verify_authorisation_by_owner('obj_id')
    def grant_access(self, obj_id: str, iid: str) -> (Response, int):
        # do we have this data object?
        if not self._node.db.get_object_by_id(obj_id):
            raise DataObjectNotFoundError(obj_id)

        # do we have an identity for this iid?
        identity = self._node.db.get_identity(iid)
        if identity is None:
            raise IdentityNotFoundError(iid)

        self._node.db.grant_access(obj_id, identity)
        return create_ok_response(self._node.db.get_access_list(obj_id))

    @request_manager.require_dor()
    @request_manager.verify_authorisation_by_owner('obj_id')
    def revoke_access(self, obj_id: str, iid: str) -> (Response, int):
        # do we have this data object?
        record = self._node.db.get_object_by_id(obj_id)
        if not record:
            raise DataObjectNotFoundError(obj_id)

        # do we have an identity for this iid?
        identity = self._node.db.get_identity(iid)
        if identity is None:
            raise IdentityNotFoundError(iid)

        self._node.db.revoke_access(obj_id, identity)
        return create_ok_response(self._node.db.get_access_list(obj_id))

    @request_manager.require_dor()
    def get_owner(self, obj_id: str) -> (Response, int):
        # do we have this data object?
        if not self._node.db.get_object_by_id(obj_id):
            raise DataObjectNotFoundError(obj_id)

        # do we have the owner identity
        owner = self._node.db.get_owner(obj_id)
        if not owner:
            raise OwnerIdentityNotFoundError(obj_id, owner.id)

        return create_ok_response({
            'obj_id': obj_id,
            'owner_iid': owner.id
        })

    @request_manager.require_dor()
    @request_manager.verify_request_body(transfer_ownership_body_specification)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def transfer_ownership(self, obj_id: str) -> (Response, int):
        # do we have this data object?
        record = self._node.db.get_object_by_id(obj_id)
        if not record:
            raise DataObjectNotFoundError(obj_id)

        body = request_manager.get_request_variable('body')
        new_owner = self._node.db.get_identity(body['new_owner_iid'])
        if new_owner is None:
            raise OwnerIdentityNotFoundError(obj_id, body['new_owner_iid'])

        content_key = body['content_key'] if 'content_key' in body else None
        self._node.db.update_ownership(obj_id, new_owner, content_key)

        # retrieve the owner of the data object
        owner = self._node.db.get_owner(obj_id)
        return create_ok_response({
            'obj_id': obj_id,
            'owner_iid': owner.id
        })

    @request_manager.require_dor()
    def get_tags(self, obj_id: str) -> (Response, int):
        # do we have this data object?
        if not self._node.db.get_object_by_id(obj_id):
            raise DataObjectNotFoundError(obj_id)

        return create_ok_response(self._node.db.get_tags(obj_id))

    @request_manager.require_dor()
    @request_manager.verify_request_body(tags_body_specification)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def update_tags(self, obj_id: str) -> (Response, int):
        # do we have this data object?
        if not self._node.db.get_object_by_id(obj_id):
            raise DataObjectNotFoundError(obj_id)

        body = request_manager.get_request_variable('body')
        self._node.db.update_tags(obj_id, body)
        return create_ok_response(self._node.db.get_tags(obj_id))

    @request_manager.require_dor()
    @request_manager.verify_request_body(delete_tags_body_specification)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def remove_tags(self, obj_id: str) -> (Response, int):
        # do we have this data object?
        if not self._node.db.get_object_by_id(obj_id):
            raise DataObjectNotFoundError(obj_id)

        body = request_manager.get_request_variable('body')
        self._node.db.remove_tags(obj_id, body)
        return create_ok_response(self._node.db.get_tags(obj_id))


class DORProxy(EndpointProxy):
    def __init__(self, remote_address):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address)

    def search(self, patterns: list[str] = None, owner_iid: str = None) -> dict:
        body = {}

        if patterns is not None and len(patterns) > 0:
            body['patterns'] = patterns

        if owner_iid is not None:
            body['owner_iid'] = owner_iid

        return self.get('', body=body)

    def add_data_object(self, content_path: str, owner: Identity, access_restricted: bool, content_encrypted: bool,
                        data_type: str, data_format: str, created_by: str,
                        created_t: int = None, recipe: dict = None) -> (str, dict):
        body = {
            'owner_iid': owner.id,
            'descriptor': {
                'data_type': data_type,
                'data_format': data_format,
                'created_t': created_t if created_t else get_timestamp_now(),
                'created_by': created_by
            },
            'access_restricted': access_restricted,
            'content_encrypted': content_encrypted
        }

        if recipe is not None:
            body['descriptor']['recipe'] = recipe

        r = self.post('/add', body=body, attachment_path=content_path)
        return r['obj_id'], r['descriptor']

    def add_gpp_data_object(self, source: str, commit_id: str, proc_path: str, proc_config: str, owner: Identity,
                            created_by: str, created_t: int = None, recipe: dict = None) -> (str, dict):
        body = {
            'owner_iid': owner.id,
            'descriptor': {
                'data_type': 'Git-Processor-Pointer',
                'data_format': 'json',
                'created_t': created_t if created_t else get_timestamp_now(),
                'created_by': created_by
            },
            'gpp': {
                'source': source,
                'commit_id': commit_id,
                'proc_path': proc_path,
                'proc_config': proc_config
            }
        }

        if recipe is not None:
            body['descriptor']['recipe'] = recipe

        # execute post request and remove temp file afterwards
        r = self.post('/add-gpp', body=body)
        return r['obj_id'], r['descriptor']

    def delete_data_object(self, obj_id: str, with_authorisation_by: Keystore) -> (str, dict):
        r = self.delete(f"/{obj_id}", with_authorisation_by=with_authorisation_by)
        return r['obj_id'], r['descriptor']

    def get_descriptor(self, obj_id: str) -> (str, dict):
        r = self.get(f"/{obj_id}/descriptor")
        return r['obj_id'], r['descriptor']

    def get_content(self, obj_id: str, with_authorisation_by: Keystore, download_path: str):
        return self.get(f"/{obj_id}/content", download_path=download_path, with_authorisation_by=with_authorisation_by)

    def get_access_overview(self, obj_id: str) -> list:
        return self.get(f"/{obj_id}/access")

    def grant_access(self, obj_id: str, authority: Keystore, identity: Identity) -> dict:
        return self.post(f"/{obj_id}/access/{identity.id}", with_authorisation_by=authority)

    def revoke_access(self, obj_id: str, authority: Keystore, identity: Identity) -> dict:
        return self.delete(f"/{obj_id}/access/{identity.id}", with_authorisation_by=authority)

    def get_owner(self, obj_id: str) -> dict:
        return self.get(f"/{obj_id}/owner")

    def transfer_ownership(self, obj_id: str, authority: Keystore, new_owner: Identity, content_key: str = None):
        body = {
            'new_owner_iid': new_owner.id
        }

        if content_key is not None:
            body['content_key'] = content_key

        return self.put(f"/{obj_id}/owner", body, with_authorisation_by=authority)

    def get_tags(self, obj_id: str) -> dict:
        return self.get(f"/{obj_id}/tags")

    def update_tags(self, obj_id: str, authority: Keystore, tags: dict) -> dict:
        body = []
        for key, value in tags.items():
            body.append({
                'key': key,
                'value': value
            })

        return self.put(f"/{obj_id}/tags", body=body, with_authorisation_by=authority)

    def remove_tags(self, obj_id: str, authority: Keystore, keys: list) -> dict:
        return self.delete(f"/{obj_id}/tags", body=keys, with_authorisation_by=authority)
