import os
from typing import Optional, List, Union

from flask import Response
from pydantic import BaseModel
from saascore.api.sdk.helpers import create_ok_response, create_ok_attachment
from saascore.api.sdk.proxies import dor_endpoint_prefix
from saascore.log import Logging

from saas.dor.exceptions import DataObjectNotFoundError, DataObjectContentNotFoundError, IdentityNotFoundError
from saascore.keystore.assets.credentials import GithubCredentials

from saas.rest.blueprint import SaaSBlueprint
from saas.schemas import GitProcessorPointer, ObjectRecipe, ObjectTag
from saas.rest.request_manager import request_manager

logger = Logging.get('dor.blueprint')


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
    class GPPGitHubCredentials(BaseModel):
        login: str
        personal_access_token: str
    
    github_credentials: Optional[GPPGitHubCredentials]


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
    c_hashes: Optional[List[str]]


class DORStatistics(BaseModel):
    data_types: List[str]
    data_formats: List[str]
    tag_keys: List[str]


class DORBlueprint(SaaSBlueprint):
    def __init__(self, node):
        super().__init__('repository', __name__, dor_endpoint_prefix)
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


