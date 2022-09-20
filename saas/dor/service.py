import json
import os
import shutil
import subprocess
from stat import S_IREAD, S_IRGRP
from tempfile import NamedTemporaryFile
from typing import Optional, List

from fastapi import UploadFile, Request, Form, File
from saascore.api.sdk.exceptions import AuthorisationFailedError
from saascore.api.sdk.proxies import dor_endpoint_prefix
from saascore.cryptography.helpers import hash_file_content
from saascore.log import Logging
from saascore.helpers import write_json_to_file, read_json_from_file, validate_json, generate_random_string
from saascore.keystore.assets.credentials import GithubCredentials
from saascore.keystore.identity import Identity
from starlette.responses import FileResponse, Response

from saas.dor.exceptions import CloneRepositoryError, CheckoutCommitError, ProcessorDescriptorNotFoundError, \
    InvalidProcessorDescriptorError, InvalidGPPDataObjectError, IdentityNotFoundError, DataObjectContentNotFoundError, \
    DataObjectNotFoundError
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.dor.schemas import DataObject, SearchParameters, DORStatistics, AddDataObjectParameters, \
    AddGPPDataObjectParameters, Tag
from saas.rest.auth import VerifyAuthorisation
from saas.rest.schemas import EndpointDefinition
from saas.schemas import ProcessorDescriptor, GitProcessorPointer, ObjectRecipe

logger = Logging.get('dor.service')


class DataObjectRepositoryService:
    infix_master_path = 'dor-master'
    infix_temp_path = 'dor-temp'

    def __init__(self, node) -> None:
        # initialise properties
        self._node = node
        self._protocol = DataObjectRepositoryP2PProtocol(node)

        # initialise directories
        os.makedirs(os.path.join(self._node.datastore, DataObjectRepositoryService.infix_master_path), exist_ok=True)
        os.makedirs(os.path.join(self._node.datastore, DataObjectRepositoryService.infix_temp_path), exist_ok=True)

    def obj_content_path(self, c_hash: str) -> str:
        return os.path.join(self._node.datastore, DataObjectRepositoryService.infix_master_path, c_hash)

    def add_gpp(self, created_by: str, gpp: dict, owner_iid: str, recipe: Optional[dict],
                github_credentials: Optional[GithubCredentials]) -> dict:
        # get the owner identity
        owner = self._node.db.get_identity(owner_iid)
        if owner is None:
            raise IdentityNotFoundError(owner_iid)

        # verify the GPP object
        if not validate_json(gpp, GitProcessorPointer.schema()):
            raise InvalidGPPDataObjectError({
                'gpp': gpp
            })

        # determine URL including credentials (if any)
        url = gpp['source']
        if github_credentials:
            insert = f"{github_credentials.login}:{github_credentials.personal_access_token}@"
            index = url.find('github.com')
            url = url[:index] + insert + url[index:]

        # try to clone the repository
        temp_id = generate_random_string(8)
        repo_path = os.path.join(self._node.datastore, DataObjectRepositoryService.infix_temp_path, f"{temp_id}.repo")
        result = subprocess.run(['git', 'clone', url, repo_path], capture_output=True)
        if result.returncode != 0:
            raise CloneRepositoryError({
                'url': url,
                'stdout': result.stdout.decode('utf-8'),
                'stderr': result.stderr.decode('utf-8')
            })

        # try to checkout the specific commit
        result = subprocess.run(['git', 'checkout', gpp['commit_id']], capture_output=True, cwd=repo_path)
        if result.returncode != 0:
            raise CheckoutCommitError({
                'commit-id': gpp['commit-id'],
                'stdout': result.stdout.decode('utf-8'),
                'stderr': result.stderr.decode('utf-8')
            })

        # does the processor descriptor exist?
        proc_descriptor_path = os.path.join(repo_path, gpp['proc_path'], 'descriptor.json')
        if not os.path.isfile(proc_descriptor_path):
            raise ProcessorDescriptorNotFoundError({
                'gpp': gpp,
                'proc_descriptor_path': proc_descriptor_path
            })

        # read the processor descriptor
        gpp['proc_descriptor'] = read_json_from_file(proc_descriptor_path)
        if not validate_json(gpp['proc_descriptor'], ProcessorDescriptor.schema()):
            raise InvalidProcessorDescriptorError({
                'gpp': gpp
            })

        # we don't need the repository anymore -> delete it
        shutil.rmtree(repo_path)

        # store the GPP object to a temporary location and generate the c_cash
        gpp_path = os.path.join(self._node.datastore, DataObjectRepositoryService.infix_temp_path, f"{temp_id}.gpp")
        write_json_to_file(gpp, gpp_path)
        c_hash = hash_file_content(gpp_path).hex()

        return self._add(c_hash, gpp_path, 'Git-Processor-Pointer', 'json', created_by,
                         recipe, gpp, owner, False, False)

    def add(self, temp_content_path: str, data_type: str, data_format: str, created_by: str,
            recipe: Optional[ObjectRecipe], owner_iid: str, access_restricted: bool, content_encrypted: bool) -> dict:

        # get the owner identity
        owner = self._node.db.get_identity(owner_iid)
        if owner is None:
            raise IdentityNotFoundError(owner_iid)

        # calculate the hash for the data object content
        c_hash = hash_file_content(temp_content_path).hex()

        return self._add(c_hash, temp_content_path, data_type, data_format, created_by,
                         recipe, None, owner, access_restricted, content_encrypted)

    def _add(self, c_hash: str, temp_content_path: str, data_type: str, data_format: str,
             created_by: str, recipe: Optional[ObjectRecipe], gpp: Optional[dict],
             owner: Identity, access_restricted: bool, content_encrypted: bool) -> dict:

        # check if there are already data objects with the same content
        if len(self._node.db.get_objects_by_content_hash(c_hash)) > 0:
            # it is possible for cases like this to happen. despite the exact same content, this may well be
            # a legitimate different data object. for example, different provenance has led to the exact same
            # outcome. we thus create a new data object
            logger.info(f"data object content '{c_hash}' already exists -> not adding content to DOR.")

            # delete the temporary content as it is not needed
            os.remove(temp_content_path)

        else:
            logger.info(f"data object content '{c_hash}' does not exist yet -> adding content to DOR.")

            # move the temporary content to its destination and make it read-only
            destination_path = self.obj_content_path(c_hash)
            os.rename(temp_content_path, destination_path)
            os.chmod(destination_path, S_IREAD | S_IRGRP)

        # add the recipe (if any) and broadcast it
        if recipe is not None:
            # insert the missing c_hash
            recipe.product.c_hash = c_hash

            # add the recipe to the NodeDB
            r_hash = self._node.db.add_recipe(c_hash, recipe.dict())
            self._node.db.protocol.broadcast_update('add_recipe', {
                'c_hash': c_hash,
                'recipe': recipe.dict()
            })
        else:
            r_hash = None

        # add data object to database
        record = self._node.db.add_data_object(c_hash, r_hash, data_type, data_format, created_by, gpp,
                                               owner, access_restricted, content_encrypted)
        obj_id = record['obj_id']
        logger.info(f"database records for data object '{obj_id}' added with c_hash={c_hash}.")

        return record

    def delete(self, obj_id: str) -> dict:
        # delete the database entries associated with this data object EXCEPT for the provenance information
        record = self._node.db.remove_data_object(obj_id)
        logger.info(f"database records for data object '{obj_id}' deleted.")

        # next we need to check if there are other data objects that point to the same content (very unlikely but
        # not impossible) AND still expect the data object content to be available. if so, then do NOT delete the
        # data object content. otherwise delete it.
        referenced = [r['obj_id'] for r in self._node.db.get_objects_by_content_hash(record['c_hash'])]

        if len(referenced) == 0:
            logger.info(f"data object content '{record['c_hash']}' not referenced by any data object -> delete.")
            content_path = self.obj_content_path(record['c_hash'])
            os.remove(content_path)
        else:
            logger.info(f"data object content '{record['c_hash']}' referenced by data objects ({referenced}) -> "
                        f"do not delete.")

        return record


class VerifyIsOwner:
    def __init__(self, node):
        self.node = node

    async def __call__(self, obj_id: str, request: Request):
        identity, body = await VerifyAuthorisation(self.node).__call__(request)

        # get the meta information of the object
        meta = self.node.db.get_object_by_id(obj_id)
        if meta is None:
            raise AuthorisationFailedError({
                'reason': 'data object does not exist',
                'obj_id': obj_id
            })

        # check if the identity is the owner of that data object
        if meta['owner_iid'] != identity.id:
            raise AuthorisationFailedError({
                'reason': 'user is not the data object owner',
                'obj_id': obj_id,
                'user_iid': identity.id
            })


class VerifyUserHasAccess:
    def __init__(self, node):
        self.node = node

    async def __call__(self, obj_id: str, request: Request):
        identity, body = await VerifyAuthorisation(self.node).__call__(request)

        # get the meta information of the object
        meta = self.node.db.get_object_by_id(obj_id)
        if meta is None:
            raise AuthorisationFailedError({
                'reason': 'data object does not exist',
                'obj_id': obj_id
            })

        # check if the identity has access to the data object content
        if identity.id not in meta['access']:
            raise AuthorisationFailedError({
                'reason': 'user has no access to the data object content',
                'obj_id': obj_id,
                'user_iid': identity.id
            })


class RESTDataObjectRepositoryService(DataObjectRepositoryService):
    def endpoints(self) -> list:
        return [
            EndpointDefinition(method='GET', prefix=dor_endpoint_prefix, rule='',
                               function=self.rest_search, response_model=List[DataObject]),

            EndpointDefinition(method='GET', prefix=dor_endpoint_prefix, rule='statistics',
                               function=self.rest_statistics, response_model=DORStatistics),

            EndpointDefinition(method='POST', prefix=dor_endpoint_prefix, rule='add',
                               function=self.rest_add, response_model=DataObject),

            EndpointDefinition(method='POST', prefix=dor_endpoint_prefix, rule='add-gpp',
                               function=self.rest_add_gpp, response_model=DataObject),

            EndpointDefinition(method='DELETE', prefix=dor_endpoint_prefix, rule='{obj_id}',
                               function=self.rest_delete, response_model=DataObject,
                               dependencies=[VerifyIsOwner]),

            EndpointDefinition(method='GET', prefix=dor_endpoint_prefix, rule='{obj_id}/meta',
                               function=self.rest_get_meta, response_model=Optional[DataObject]),

            EndpointDefinition(method='GET', prefix=dor_endpoint_prefix, rule='{obj_id}/content',
                               function=self.rest_get_content, response_model=None,
                               dependencies=[VerifyUserHasAccess]),

            EndpointDefinition(method='POST', prefix=dor_endpoint_prefix, rule='{obj_id}/access/{iid}',
                               function=self.rest_grant_access, response_model=DataObject,
                               dependencies=[VerifyIsOwner]),

            EndpointDefinition(method='DELETE', prefix=dor_endpoint_prefix, rule='{obj_id}/access/{iid}',
                               function=self.rest_revoke_access, response_model=DataObject,
                               dependencies=[VerifyIsOwner]),

            EndpointDefinition(method='PUT', prefix=dor_endpoint_prefix, rule='{obj_id}/owner/{iid}',
                               function=self.rest_transfer_ownership, response_model=DataObject,
                               dependencies=[VerifyIsOwner]),

            EndpointDefinition(method='PUT', prefix=dor_endpoint_prefix, rule='{obj_id}/tags',
                               function=self.rest_update_tags, response_model=DataObject,
                               dependencies=[VerifyIsOwner]),

            EndpointDefinition(method='DELETE', prefix=dor_endpoint_prefix, rule='{obj_id}/tags',
                               function=self.rest_remove_tags, response_model=DataObject,
                               dependencies=[VerifyIsOwner])
        ]

    def rest_search(self, parameters: SearchParameters) -> List[DataObject]:
        return self._node.db.find_data_objects(parameters.patterns, parameters.owner_iid, parameters.data_type,
                                               parameters.data_format, parameters.c_hashes)

    def rest_statistics(self) -> DORStatistics:
        return self._node.db.get_statistics()

    def rest_add(self, body: str = Form(...), attachment: UploadFile = File(...)) -> DataObject:
        p = AddDataObjectParameters.parse_obj(json.loads(body))

        # write contents to file
        temp = NamedTemporaryFile(delete=False)
        with temp as f:
            f.write(attachment.file.read())

        # add contents to DOR
        result = self._node.dor.add(temp.name, p.data_type, p.data_format, p.created_by, p.recipe, p.owner_iid,
                                    p.access_restricted, p.content_encrypted)

        # check if temp file still exists.
        if os.path.exists(temp.name):
            logger.warning(f"temporary file {temp.name} still exists after adding to DOR -> deleting. meta={result}")
            os.remove(temp.name)

        return result

    def rest_add_gpp(self, p: AddGPPDataObjectParameters) -> DataObject:
        github_credentials = GithubCredentials(
            login=p.github_credentials.login,
            personal_access_token=p.github_credentials.personal_access_token) if p.github_credentials else None

        return self._node.dor.add_gpp(p.created_by, p.gpp.dict(), p.owner_iid, p.recipe, github_credentials)

    def rest_delete(self, obj_id: str) -> DataObject:
        return self._node.dor.delete(obj_id)

    def rest_get_meta(self, obj_id: str) -> Optional[DataObject]:
        record = self._node.db.get_object_by_id(obj_id)
        return record if record else None

    def rest_get_content(self, obj_id: str) -> Response:
        # do we have this data object?
        record = self._node.db.get_object_by_id(obj_id)
        if not record:
            raise DataObjectNotFoundError(obj_id)

        content_path = self._node.dor.obj_content_path(record['c_hash'])
        if not os.path.isfile(content_path):
            raise DataObjectContentNotFoundError({
                'path': content_path
            })

        return FileResponse(content_path, media_type='application/octet-stream')

    def rest_grant_access(self, obj_id: str, iid: str) -> DataObject:
        # do we have this data object?
        if not self._node.db.get_object_by_id(obj_id):
            raise DataObjectNotFoundError(obj_id)

        # do we have an identity for this iid?
        identity = self._node.db.get_identity(iid)
        if identity is None:
            raise IdentityNotFoundError(iid)

        self._node.db.grant_access(obj_id, identity)
        return self._node.db.get_object_by_id(obj_id)

    def rest_revoke_access(self, obj_id: str, iid: str) -> DataObject:
        # do we have this data object?
        record = self._node.db.get_object_by_id(obj_id)
        if not record:
            raise DataObjectNotFoundError(obj_id)

        # do we have an identity for this iid?
        identity = self._node.db.get_identity(iid)
        if identity is None:
            raise IdentityNotFoundError(iid)

        self._node.db.revoke_access(obj_id, identity)
        return self._node.db.get_object_by_id(obj_id)

    def rest_transfer_ownership(self, obj_id: str, iid: str) -> DataObject:
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
        return self._node.db.get_object_by_id(obj_id)

    def rest_update_tags(self, obj_id: str, tags: List[Tag]) -> DataObject:
        # do we have this data object?
        if not self._node.db.get_object_by_id(obj_id):
            raise DataObjectNotFoundError(obj_id)

        self._node.db.update_tags(obj_id, tags)
        return self._node.db.get_object_by_id(obj_id)

    def rest_remove_tags(self, obj_id: str, keys: List[str]) -> DataObject:
        # do we have this data object?
        if not self._node.db.get_object_by_id(obj_id):
            raise DataObjectNotFoundError(obj_id)

        self._node.db.remove_tags(obj_id, keys)
        return self._node.db.get_object_by_id(obj_id)
