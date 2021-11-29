import os
from typing import Optional, List, Union

from flask import Response
from pydantic import BaseModel

from saas.dor.exceptions import DataObjectNotFoundError, DataObjectContentNotFoundError, IdentityNotFoundError
from saas.keystore.assets.credentials import GithubCredentials
from saas.keystore.identity import Identity
from saas.keystore.keystore import Keystore
from saas.logging import Logging
from saas.rest.blueprint import SaaSBlueprint, create_ok_response, create_ok_attachment
from saas.schemas import GitProcessorPointer, ObjectRecipe, ObjectTag
from saas.rest.proxy import EndpointProxy
from saas.rest.request_manager import request_manager

logger = Logging.get('dor.blueprint')
endpoint_prefix = "/api/v1/repository"


class SaaSObject(BaseModel):
    data_type: str
    data_format: str
    created_by: str
    recipe: Optional[ObjectRecipe]
    owner_iid: str


class DataObject(SaaSObject):
    access_restricted: bool
    content_encrypted: bool


class GPPObject(SaaSObject):
    gpp: GitProcessorPointer


class GPPObjectWithCredentials(GPPObject):
    class GitHubCredentials(BaseModel):
        login: str
        personal_access_token: str
    
    github_credentials: Optional[GithubCredentials]


class ObjectTagKeys(BaseModel):
    __root__: List[str]


class ObjectTags(BaseModel):
    __root__: List[ObjectTag]


class DORObject(BaseModel):
    class AdditionalProperties(BaseModel):
        obj_id: str
        c_hash: str
        created_t: int
        tags: List[ObjectTag]
        access: List[str]

    class DORDataObject(DataObject, AdditionalProperties):
        pass

    class DORGPPObject(GPPObject, AdditionalProperties):
        pass

    __root__: Union[DORDataObject, DORGPPObject]


class DORObjects(BaseModel):
    __root__: List[DORObject]


class ObjectSearchParameters(BaseModel):
    owner_iid: Optional[str]
    data_type: Optional[str]
    data_format: Optional[str]
    patterns: Optional[List[str]]


class DORStatistics(BaseModel):
    data_types: List[str]
    data_formats: List[str]
    tag_keys: List[str]


class DORBlueprint(SaaSBlueprint):
    def __init__(self, node):
        super().__init__('repository', __name__, endpoint_prefix)
        self._node = node

        self.add_rule('', self.search, ['GET'])
        self.add_rule('statistics', self.statistics, ['GET'])
        self.add_rule('add', self.add, ['POST'])
        self.add_rule('add-gpp', self.add_gpp, ['POST'])
        self.add_rule('<obj_id>', self.delete, ['DELETE'])
        self.add_rule('<obj_id>/meta', self.get_meta, ['GET'])
        self.add_rule('<obj_id>/content', self.get_content, ['GET'])
        self.add_rule('<obj_id>/access/<iid>', self.grant_access, ['POST'])
        self.add_rule('<obj_id>/access/<iid>', self.revoke_access, ['DELETE'])
        self.add_rule('<obj_id>/owner/<iid>', self.transfer_ownership, ['PUT'])
        self.add_rule('<obj_id>/tags', self.update_tags, ['PUT'])
        self.add_rule('<obj_id>/tags', self.remove_tags, ['DELETE'])

    @request_manager.handle_request(DORObjects)
    @request_manager.require_dor()
    @request_manager.verify_request_body(ObjectSearchParameters)
    def search(self) -> (Response, int):
        body = request_manager.get_request_variable('body')
        patterns = body.get('patterns')
        owner_iid = body.get('owner_iid')
        data_type = body.get('data_type')
        data_format = body.get('data_format')
        c_hashes = body.get('c_hashes')
        return create_ok_response(self._node.db.find_data_objects(patterns, owner_iid,
                                                                  data_type, data_format,
                                                                  c_hashes))

    @request_manager.handle_request(DORStatistics)
    @request_manager.require_dor()
    def statistics(self) -> (Response, int):
        return create_ok_response(self._node.db.get_statistics())

    @request_manager.handle_request(DORObject)
    @request_manager.require_dor()
    @request_manager.verify_request_body(DataObject)
    @request_manager.verify_request_files(['attachment'])
    def add(self) -> (Response, int):
        body = request_manager.get_request_variable('body')
        files = request_manager.get_request_variable('files')
        return create_ok_response(self._node.dor.add(files['attachment'],
                                                     body['data_type'], body['data_format'], body['created_by'],
                                                     body['recipe'] if 'recipe' in body else None,
                                                     body['owner_iid'],
                                                     body['access_restricted'], body['content_encrypted']))

    @request_manager.handle_request(DORObject)
    @request_manager.require_dor()
    @request_manager.verify_request_body(GPPObjectWithCredentials)
    def add_gpp(self) -> (Response, int):
        body = request_manager.get_request_variable('body')

        github_credentials = GithubCredentials(login=body['github_credentials']['login'],
                                               personal_access_token=body['github_credentials']['personal_access_token']) \
            if 'github_credentials' in body else None

        return create_ok_response(self._node.dor.add_gpp(body['created_by'], body['gpp'], body['owner_iid'],
                                                         body['recipe'] if 'recipe' in body else None,
                                                         github_credentials))

    @request_manager.handle_request(DORObject)
    @request_manager.require_dor()
    @request_manager.verify_authorisation_by_owner('obj_id')
    def delete(self, obj_id: str) -> (Response, int):
        return create_ok_response(self._node.dor.delete(obj_id))

    @request_manager.handle_request(DORObject)
    @request_manager.require_dor()
    def get_meta(self, obj_id: str) -> (Response, int):
        record = self._node.db.get_object_by_id(obj_id)
        if record is None:
            raise DataObjectNotFoundError(obj_id)
        return create_ok_response(record)

    @request_manager.handle_request()
    @request_manager.require_dor()
    @request_manager.verify_authorisation_by_user('obj_id')
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

    @request_manager.handle_request(DORObject)
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
        return create_ok_response(self._node.db.get_object_by_id(obj_id))

    @request_manager.handle_request(DORObject)
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
        return create_ok_response(self._node.db.get_object_by_id(obj_id))

    @request_manager.handle_request(DORObject)
    @request_manager.require_dor()
    @request_manager.verify_authorisation_by_owner('obj_id')
    def transfer_ownership(self, obj_id: str, iid: str) -> (Response, int):
        # do we have this data object?
        record = self._node.db.get_object_by_id(obj_id)
        if not record:
            raise DataObjectNotFoundError(obj_id)

        # get the identity of the new owner
        new_owner = self._node.db.get_identity(iid)
        if new_owner is None:
            raise IdentityNotFoundError(iid)

        # transfer ownership
        self._node.db.update_ownership(obj_id, new_owner)
        return create_ok_response(self._node.db.get_object_by_id(obj_id))

    @request_manager.handle_request(DORObject)
    @request_manager.require_dor()
    @request_manager.verify_request_body(ObjectTags)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def update_tags(self, obj_id: str) -> (Response, int):
        # do we have this data object?
        if not self._node.db.get_object_by_id(obj_id):
            raise DataObjectNotFoundError(obj_id)

        body = request_manager.get_request_variable('body')
        self._node.db.update_tags(obj_id, body)
        return create_ok_response(self._node.db.get_object_by_id(obj_id))

    @request_manager.handle_request(DORObject)
    @request_manager.require_dor()
    @request_manager.verify_request_body(ObjectTagKeys)
    @request_manager.verify_authorisation_by_owner('obj_id')
    def remove_tags(self, obj_id: str) -> (Response, int):
        # do we have this data object?
        if not self._node.db.get_object_by_id(obj_id):
            raise DataObjectNotFoundError(obj_id)

        body = request_manager.get_request_variable('body')
        self._node.db.remove_tags(obj_id, body)
        return create_ok_response(self._node.db.get_object_by_id(obj_id))


class DORProxy(EndpointProxy):
    def __init__(self, remote_address):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address)

    def search(self, patterns: list[str] = None, owner_iid: str = None,
               data_type: str = None, data_format: str = None,
               c_hashes: list[str] = None) -> dict:
        body = {}

        if patterns is not None and len(patterns) > 0:
            body['patterns'] = patterns

        if owner_iid is not None:
            body['owner_iid'] = owner_iid

        if data_type is not None:
            body['data_type'] = data_type

        if data_format is not None:
            body['data_format'] = data_format

        if c_hashes is not None:
            body['c_hashes'] = c_hashes

        return self.get('', body=body)

    def statistics(self) -> dict:
        return self.get('/statistics')

    def add_data_object(self, content_path: str, owner: Identity, access_restricted: bool, content_encrypted: bool,
                        data_type: str, data_format: str, created_by: str, recipe: dict = None) -> dict:
        body = {
            'data_type': data_type,
            'data_format': data_format,
            'created_by': created_by,
            'owner_iid': owner.id,
            'access_restricted': access_restricted,
            'content_encrypted': content_encrypted
        }

        if recipe is not None:
            body['recipe'] = recipe

        return self.post('/add', body=body, attachment_path=content_path)

    def add_gpp_data_object(self, source: str, commit_id: str, proc_path: str, proc_config: str, owner: Identity,
                            created_by: str, recipe: dict = None, github_credentials: GithubCredentials = None) -> dict:
        body = {
            'data_type': 'Git-Processor-Pointer',
            'data_format': 'json',
            'created_by': created_by,
            'owner_iid': owner.id,
            'gpp': {
                'source': source,
                'commit_id': commit_id,
                'proc_path': proc_path,
                'proc_config': proc_config
            }
        }

        if recipe is not None:
            body['recipe'] = recipe

        if github_credentials:
            body['github_credentials'] = {
                'login': github_credentials.login,
                'personal_access_token': github_credentials.personal_access_token
            }

        return self.post('/add-gpp', body=body)

    def delete_data_object(self, obj_id: str, with_authorisation_by: Keystore) -> (str, dict):
        return self.delete(f"/{obj_id}", with_authorisation_by=with_authorisation_by)

    def get_meta(self, obj_id: str) -> (str, dict):
        return self.get(f"/{obj_id}/meta")

    def get_content(self, obj_id: str, with_authorisation_by: Keystore, download_path: str) -> dict:
        return self.get(f"/{obj_id}/content", download_path=download_path, with_authorisation_by=with_authorisation_by)

    def grant_access(self, obj_id: str, authority: Keystore, identity: Identity) -> dict:
        return self.post(f"/{obj_id}/access/{identity.id}", with_authorisation_by=authority)

    def revoke_access(self, obj_id: str, authority: Keystore, identity: Identity) -> dict:
        return self.delete(f"/{obj_id}/access/{identity.id}", with_authorisation_by=authority)

    def transfer_ownership(self, obj_id: str, authority: Keystore, new_owner: Identity) -> dict:
        # TODO: reminder that the application layer is responsible to transfer the content_key to the new owner
        return self.put(f"/{obj_id}/owner/{new_owner.id}", with_authorisation_by=authority)

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
