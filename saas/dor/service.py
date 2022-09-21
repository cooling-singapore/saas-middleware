import json
import os
import shutil
import subprocess
from stat import S_IREAD, S_IRGRP
from tempfile import NamedTemporaryFile
from typing import Optional, List, Union

from fastapi import UploadFile, Request, Form, File
from fastapi.responses import FileResponse, Response
from saascore.api.sdk.exceptions import AuthorisationFailedError
from saascore.cryptography.helpers import hash_file_content, hash_json_object, hash_string_object
from saascore.log import Logging
from saascore.helpers import read_json_from_file, validate_json, generate_random_string, get_timestamp_now
from sqlalchemy import Column, String, Integer, Boolean
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy_json import NestedMutableJson

from saas.dor.exceptions import CloneRepositoryError, CheckoutCommitError, ProcessorDescriptorNotFoundError, \
    InvalidProcessorDescriptorError, DataObjectContentNotFoundError, DataObjectNotFoundError, \
    DORException
from saas.nodedb.exceptions import IdentityNotFoundError
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.dor.schemas import DataObject, SearchParameters, AddGPPDataObjectParameters, Tag, CDataObject, \
    GPPDataObject, AddCDataObjectParameters, DataObjectRecipe, DataObjectProvenance, GitProcessorPointer, DORStatistics
from saas.rest.auth import VerifyAuthorisation
from saas.rest.schemas import EndpointDefinition
from saas.schemas import ProcessorDescriptor

logger = Logging.get('dor.service')

Base = declarative_base()

const_gpp_data_type = 'GitProcessorPointer'
const_gpp_data_format = 'json'
const_dor_infix_master_path = 'dor-master'
const_dor_infix_temp_path = 'dor-temp'


def _generate_object_id(c_hash: str, data_type: str, data_format: str, created_iid: str, created_t: int) -> str:
    # TODO: since timestamp is included the resulting object id is very much random -> consider replacing deriving
    #  object id based on hashing with generating actual random ids instead.
    return hash_string_object(f"{c_hash}{data_type}{data_format}{created_iid}{created_t}").hex()


def _generate_gpp_hash(source: str, commit_id: str, proc_path: str, proc_config: str) -> str:
    return hash_json_object({
        'source': source,
        'commit_id': commit_id,
        'proc_path': proc_path,
        'proc_config': proc_config
    }).hex()


class DataObjectRecord(Base):
    __tablename__ = 'obj_record'
    obj_id = Column(String(64), primary_key=True)

    # immutable part of the meta information
    c_hash = Column(String(64), nullable=False)
    data_type = Column(String(64), nullable=False)
    data_format = Column(String(64), nullable=False)
    creator_iid = Column(String(64), nullable=False)
    created_t = Column(Integer, nullable=False)

    # mutable part of the meta information
    owner_iid = Column(String(64), nullable=False)
    access_restricted = Column(Boolean, nullable=False)
    access = Column(NestedMutableJson, nullable=False)
    tags = Column(NestedMutableJson, nullable=False)

    # type-specific meta information
    details = Column(NestedMutableJson, nullable=False)


class DataObjectProvenanceRecord(Base):
    __tablename__ = 'obj_provenance'
    c_hash = Column(String(64), primary_key=True)
    provenance = Column(NestedMutableJson, nullable=False)


class VerifyIsOwner:
    def __init__(self, node):
        self.node = node

    async def __call__(self, obj_id: str, request: Request):
        identity, body = await VerifyAuthorisation(self.node).__call__(request)

        # get the meta information of the object
        meta = self.node.dor.get_meta(obj_id)
        if meta is None:
            raise AuthorisationFailedError({
                'reason': 'data object does not exist',
                'obj_id': obj_id
            })

        # check if the identity is the owner of that data object
        if meta.owner_iid != identity.id:
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
        meta = self.node.dor.get_meta(obj_id)
        if meta is None:
            raise AuthorisationFailedError({
                'reason': 'data object does not exist',
                'obj_id': obj_id
            })

        # check if the identity has access to the data object content
        if identity.id not in meta.access:
            raise AuthorisationFailedError({
                'reason': 'user has no access to the data object content',
                'obj_id': obj_id,
                'user_iid': identity.id
            })


class DORService:
    def __init__(self, node, endpoint_prefix: str, db_path: str):
        # initialise properties
        self._node = node
        self._endpoint_prefix = endpoint_prefix
        self._protocol = DataObjectRepositoryP2PProtocol(node)

        # initialise database things
        self._engine = create_engine(db_path)
        Base.metadata.create_all(self._engine)
        self._Session = sessionmaker(bind=self._engine)

        # initialise directories
        os.makedirs(os.path.join(self._node.datastore, const_dor_infix_master_path), exist_ok=True)
        os.makedirs(os.path.join(self._node.datastore, const_dor_infix_temp_path), exist_ok=True)

    def obj_content_path(self, c_hash: str) -> str:
        return os.path.join(self._node.datastore, const_dor_infix_master_path, c_hash)

    def _get_object_records_by_content_hash(self, c_hash: str) -> list[DataObjectRecord]:
        with self._Session() as session:
            return session.query(DataObjectRecord).filter_by(c_hash=c_hash).all()

    def _get_recipes_by_content_hash(self, c_hash: str) -> list[DataObjectRecipe]:
        recipes = []
        records: List[DataObjectRecord] = self._get_object_records_by_content_hash(c_hash)

        for record in records:
            details = dict(record.details)
            if record.data_type != const_gpp_data_type and details['recipe'] is not None:
                recipes.append(DataObjectRecipe.parse_obj(details['recipe']))

        return recipes

    def _generate_provenance_information(self, obj_recipe: DataObjectRecipe) -> DataObjectProvenance:
        data_nodes = []
        proc_nodes = []
        obj_mapping = {}

        # add the terminal object node
        obj_node = DataObjectProvenance.ObjectNode.parse_obj({
            'is_derived': True,
            'c_hash': obj_recipe.product.c_hash,
            'data_type': obj_recipe.product.data_type,
            'data_format': obj_recipe.product.data_format
        })
        data_nodes.append(obj_node)
        obj_mapping[obj_node] = len(data_nodes) - 1

        # process all product nodes
        pending = [(obj_node, obj_recipe)]
        while len(pending) > 0:
            product_node, product_recipe = pending.pop(0)

            # create object nodes for all consumed data objects
            consumes = {}
            for obj in product_recipe.input:
                # is there a recipe for this object?
                obj_recipe = self._get_recipes_by_content_hash(obj.c_hash)
                obj_recipe = obj_recipe[0] if len(obj_recipe) > 0 else None

                # create an object node
                obj_node = DataObjectProvenance.ObjectNode.parse_obj({
                    'is_derived': obj_recipe is not None,
                    'c_hash': obj.c_hash,
                    'data_type': obj.data_type,
                    'data_format': obj.data_format,
                    'content': obj.value if obj.value else None
                })
                data_nodes.append(obj_node)
                obj_mapping[obj_node] = len(data_nodes) - 1

                # add the object to consumes
                consumes[obj.name] = obj_mapping[obj_node]

                # add the obj and recipe to pending as it needs to be processed further
                if obj_recipe:
                    pending.append((obj_node, obj_recipe))

            proc_nodes.append(DataObjectProvenance.ProcNode.parse_obj({
                'gpp': GitProcessorPointer.parse_obj({
                    'source': product_recipe.processor.source,
                    'commit_id': product_recipe.processor.commit_id,
                    'proc_path': product_recipe.processor.proc_path,
                    'proc_config': product_recipe.processor.proc_config
                }),
                'proc_descriptor': product_recipe.processor.proc_descriptor,
                'consumes': consumes,
                'produces': obj_mapping[product_node]
            }))

        provenance = DataObjectProvenance.parse_obj({
            'data_nodes': data_nodes,
            'proc_nodes': proc_nodes
        })

        return provenance

    def endpoints(self) -> list:
        return [
            EndpointDefinition('GET', self._endpoint_prefix, '',
                               self.search, List[DataObject], None),

            EndpointDefinition('GET', self._endpoint_prefix, 'statistics',
                               self.statistics, DORStatistics, None),

            EndpointDefinition('POST', self._endpoint_prefix, 'add-c',
                               self.add_c, CDataObject, None),

            EndpointDefinition('POST', self._endpoint_prefix, 'add-gpp',
                               self.add_gpp, GPPDataObject, None),

            EndpointDefinition('DELETE', self._endpoint_prefix, '{obj_id}',
                               self.remove, Union[CDataObject, GPPDataObject], [VerifyIsOwner]),

            EndpointDefinition('GET', self._endpoint_prefix, '{obj_id}/meta',
                               self.get_meta, Optional[Union[CDataObject, GPPDataObject]], None),

            EndpointDefinition('GET', self._endpoint_prefix, '{obj_id}/content',
                               self.get_content, None, [VerifyUserHasAccess]),

            EndpointDefinition('POST', self._endpoint_prefix, '{obj_id}/access/{user_iid}',
                               self.grant_access, Union[CDataObject, GPPDataObject], [VerifyIsOwner]),

            EndpointDefinition('DELETE', self._endpoint_prefix, '{obj_id}/access/{user_iid}',
                               self.revoke_access, Union[CDataObject, GPPDataObject], [VerifyIsOwner]),

            EndpointDefinition('PUT', self._endpoint_prefix, '{obj_id}/owner/{new_owner_iid}',
                               self.transfer_ownership, Union[CDataObject, GPPDataObject], [VerifyIsOwner]),

            EndpointDefinition('PUT', self._endpoint_prefix, '{obj_id}/tags',
                               self.update_tags, Union[CDataObject, GPPDataObject],
                               [VerifyIsOwner]),

            EndpointDefinition('DELETE', self._endpoint_prefix, '{obj_id}/tags',
                               self.remove_tags, Union[CDataObject, GPPDataObject], [VerifyIsOwner])
        ]

    def search(self, p: SearchParameters) -> List[DataObject]:
        with self._Session() as session:
            # build the query and get the results
            q = session.query(DataObjectRecord).filter()

            # first, apply the search constraints (if any)
            if p.owner_iid is not None:
                q = q.filter(DataObjectRecord.owner_iid == p.owner_iid)

            if p.data_type is not None:
                q = q.filter(DataObjectRecord.data_type == p.data_type)

            if p.data_format is not None:
                q = q.filter(DataObjectRecord.data_format == p.data_format)

            if p.c_hashes is not None:
                q = q.filter(DataObjectRecord.c_hash.in_(p.c_hashes))

            object_records: list[DataObjectRecord] = q.all()

            # second, apply the search patterns (if any)
            result = []
            for record in object_records:
                # flatten all tags (keys values) into a single string for search purposes
                flattened = ' '.join(f"{tag['key']} {tag['value']}" for tag in record.tags)

                # # TODO: decide if this information should be searchable via patterns. seems odd to do this here.
                # # add meta information to make them searchable
                # flattened += f" {obj_record.data_type}"
                # flattened += f" {obj_record.data_format}"

                # check if any of the patterns is a substring the flattened string.
                # if we don't have patterns then always add the object.
                if p.patterns is None or any(pattern in flattened for pattern in p.patterns):
                    record = dict((col, getattr(record, col)) for col in record.__table__.columns.keys())
                    record = DataObject.parse_obj(record)
                    result.append(record)

            return result

    def statistics(self) -> DORStatistics:
        with self._Session() as session:
            result = {
                'data_types': [value[0] for value in session.query(DataObjectRecord.data_type).distinct()],
                'data_formats': [value[0] for value in session.query(DataObjectRecord.data_format).distinct()],
                'tag_keys': []  # sorted([value[0] for value in session.query(DataObjectTag.key).distinct()])
            }
            return DORStatistics.parse_obj(result)

    def add_c(self, body: str = Form(...), attachment: UploadFile = File(...)) -> CDataObject:
        # create parameters object
        p = AddCDataObjectParameters.parse_obj(json.loads(body))

        # get the owner and creator identity
        owner = self._node.db.get_identity(p.owner_iid, raise_if_unknown=True)
        creator = self._node.db.get_identity(p.creator_iid, raise_if_unknown=True)

        # write contents to file
        temp = NamedTemporaryFile(delete=False)
        with temp as f:
            f.write(attachment.file.read())

        # calculate the hash for the data object content
        c_hash = hash_file_content(temp.name).hex()

        # check if there are already data objects with the same content
        if len(self._get_object_records_by_content_hash(c_hash)) > 0:
            # it is possible for cases like this to happen. despite the exact same content, this may well be
            # a legitimate different data object. for example, different provenance has led to the exact same
            # outcome. we thus create a new data object.
            logger.info(f"data object content '{c_hash}' already exists -> not adding content to DOR.")

            # delete the temporary content as it is not needed
            os.remove(temp.name)

        else:
            logger.info(f"data object content '{c_hash}' does not exist yet -> adding content to DOR.")

        # move the temporary content to its destination and make it read-only
        destination_path = self.obj_content_path(c_hash)
        os.rename(temp.name, destination_path)
        os.chmod(destination_path, S_IREAD | S_IRGRP)

        # determine the object id

        created_t = get_timestamp_now()
        obj_id = _generate_object_id(c_hash, p.data_type, p.data_format, creator.id, created_t)

        with self._Session() as session:
            # add a new data object record
            r_hash = hash_json_object(p.recipe.dict()) if p.recipe is not None else None
            session.add(DataObjectRecord(obj_id=obj_id, c_hash=c_hash,
                                         data_type=p.data_type, data_format=p.data_format,
                                         creator_iid=creator.id, created_t=created_t,
                                         owner_iid=owner.id, access_restricted=p.access_restricted,
                                         access=[owner.id], tags={},
                                         details={
                                             'content_encrypted': p.content_encrypted,
                                             'r_hash': r_hash,
                                             'recipe': p.recipe
                                         }))
            session.commit()
            logger.info(f"database record for data object '{obj_id}' added with c_hash={c_hash}.")

            # generate the provenance information (if applicable)
            if p.recipe is not None:
                provenance = self._generate_provenance_information(p.recipe)
                session.add(DataObjectProvenanceRecord(c_hash=c_hash, provenance=provenance))

                session.commit()
                logger.info(f"database provenance record created for data object with c_hash={c_hash}.")

            # check if temp file still exists.
            if os.path.exists(temp.name):
                logger.warning(
                    f"temporary file {temp.name} still exists after adding to DOR -> deleting.")
                os.remove(temp.name)

            return self.get_meta(obj_id)

    def add_gpp(self, p: AddGPPDataObjectParameters) -> GPPDataObject:
        # get the owner and creator identity
        owner = self._node.db.get_identity(p.owner_iid, raise_if_unknown=True)
        creator = self._node.db.get_identity(p.creator_iid, raise_if_unknown=True)

        # determine URL including credentials (if any)
        url = p.source
        if p.github_credentials:
            insert = f"{p.github_credentials.login}:{p.github_credentials.personal_access_token}@"
            index = url.find('github.com')
            url = url[:index] + insert + url[index:]

        # try to clone the repository
        temp_id = generate_random_string(8)
        repo_path = os.path.join(self._node.datastore, const_dor_infix_temp_path, f"{temp_id}.repo")
        result = subprocess.run(['git', 'clone', url, repo_path], capture_output=True)
        if result.returncode != 0:
            raise CloneRepositoryError({
                'url': url,
                'stdout': result.stdout.decode('utf-8'),
                'stderr': result.stderr.decode('utf-8')
            })

        # try to check out the specific commit
        result = subprocess.run(['git', 'checkout', p.commit_id], capture_output=True, cwd=repo_path)
        if result.returncode != 0:
            raise CheckoutCommitError({
                'commit_id': p.commit_id,
                'stdout': result.stdout.decode('utf-8'),
                'stderr': result.stderr.decode('utf-8')
            })

        # does the processor descriptor exist?
        proc_descriptor_path = os.path.join(repo_path, p.proc_path, 'descriptor.json')
        if not os.path.isfile(proc_descriptor_path):
            raise ProcessorDescriptorNotFoundError({
                'source': p.source,
                'commit_id': p.commit_id,
                'proc_path': p.proc_path
            })

        # read the processor descriptor
        proc_descriptor = read_json_from_file(proc_descriptor_path)
        if not validate_json(proc_descriptor, ProcessorDescriptor.schema()):
            raise InvalidProcessorDescriptorError({
                'source': p.source,
                'commit_id': p.commit_id,
                'proc_path': p.proc_path,
                'proc_descriptor': proc_descriptor
            })
        proc_descriptor = ProcessorDescriptor.parse_obj(proc_descriptor)

        # check if the config is valid
        if p.proc_config not in proc_descriptor.configurations:
            raise DORException(reason=f"Processor configuration '{p.proc_config}' not supported by processor.",
                               details={
                                   'proc_config': p.proc_config,
                                   'proc_descriptor': proc_descriptor
                               })

        # we don't need the repository anymore -> delete it
        shutil.rmtree(repo_path)

        # determine the content hash for the GPP
        c_hash = _generate_gpp_hash(p.source, p.commit_id, p.proc_path, p.proc_config)

        with self._Session() as session:
            # determine the object id
            created_t = get_timestamp_now()
            obj_id = _generate_object_id(c_hash, const_gpp_data_type, const_gpp_data_format, creator.id, created_t)

            # add a new data object record
            session.add(DataObjectRecord(obj_id=obj_id, c_hash=c_hash,
                                         data_type=const_gpp_data_type, data_format=const_gpp_data_format,
                                         creator_iid=creator.id, created_t=created_t,
                                         owner_iid=owner.id, access_restricted=False, access=[owner.id],
                                         tags={},
                                         details={
                                             'source': p.source,
                                             'commit_id': p.commit_id,
                                             'proc_path': p.proc_path,
                                             'proc_config': p.proc_path,
                                             'proc_descriptor': proc_descriptor.dict()
                                         }))

            session.commit()

            return self.get_meta(obj_id)

    def remove(self, obj_id: str) -> Optional[Union[CDataObject, GPPDataObject]]:
        # get the meta information for this object (if it exists in the first place)
        meta = self.get_meta(obj_id)
        if meta is None:
            return None

        # delete the data object
        with self._Session() as session:
            # delete the database record only (we do not delete the provenance information)
            session.query(DataObjectRecord).filter_by(obj_id=obj_id).delete()
            session.commit()

        # is it a C data object?
        if meta.data_type != const_gpp_data_type:
            # if it's a content data object, we need to check if there are other data objects that point to the same
            # content (unlikely but not impossible). if so, then do NOT delete the data object content. otherwise
            # delete it.
            referenced = self._get_object_records_by_content_hash(meta.c_hash)
            referenced = [record.obj_id for record in referenced]
            if len(referenced) == 0:
                logger.info(f"data object content '{meta.c_hash}' not referenced by any data object -> delete.")
                content_path = self.obj_content_path(meta.c_hash)
                os.remove(content_path)
            else:
                logger.info(f"data object content '{meta.c_hash}' referenced by data objects ({referenced}) -> "
                            f"do not delete.")

        return meta

    def get_meta(self, obj_id: str) -> Optional[Union[CDataObject, GPPDataObject]]:
        with self._Session() as session:
            # do we have an object with this id?
            record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
            if record is None:
                return None

            # is it a GPP data object?
            details = dict(record.details)
            if record.data_type == const_gpp_data_type:
                return GPPDataObject.parse_obj({
                    'obj_id': record.obj_id,
                    'c_hash': record.c_hash,
                    'data_type': record.data_type,
                    'data_format': record.data_format,
                    'creator_iid': record.creator_iid,
                    'created_t': record.created_t,
                    'owner_iid': record.owner_iid,
                    'access_restricted': record.access_restricted,
                    'access': record.access,
                    'tags': record.tags,

                    'source': details['source'],
                    'commit_id': details['commit_id'],
                    'proc_path': details['proc_path'],
                    'proc_config': details['proc_path'],
                    'proc_descriptor': details['proc_descriptor']
                })

            else:
                return CDataObject.parse_obj({
                    'obj_id': record.obj_id,
                    'c_hash': record.c_hash,
                    'data_type': record.data_type,
                    'data_format': record.data_format,
                    'creator_iid': record.creator_iid,
                    'created_t': record.created_t,
                    'owner_iid': record.owner_iid,
                    'access_restricted': record.access_restricted,
                    'access': record.access,
                    'tags': record.tags,

                    'content_encrypted': details['content_encrypted'],
                    'recipe': details['recipe'] if 'recipe' in details else None,
                    'r_hash': details['r_hash'] if 'r_hash' in details else None
                })

    def get_content(self, obj_id: str) -> Response:
        # get the meta information for this object (if it exists in the first place)
        meta = self.get_meta(obj_id)
        if meta is None:
            raise DataObjectNotFoundError(obj_id)

        # check if we have the content
        content_path = self.obj_content_path(meta.c_hash)
        if not os.path.isfile(content_path):
            raise DataObjectContentNotFoundError({
                'path': content_path
            })

        return FileResponse(content_path, media_type='application/octet-stream')

    def grant_access(self, obj_id: str, user_iid: str) -> Union[CDataObject, GPPDataObject]:
        # do we have an identity for this iid?
        user = self._node.db.get_identity(user_iid)
        if user is None:
            raise IdentityNotFoundError(user_iid)

        with self._Session() as session:
            # do we have an object with this id?
            record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
            if record is None:
                raise DataObjectNotFoundError(obj_id)

            # grant access
            if user_iid not in record.access:
                record.access.append(user_iid)
                session.commit()

        return self.get_meta(obj_id)

    def revoke_access(self, obj_id: str, user_iid: str) -> Union[CDataObject, GPPDataObject]:
        # do we have an identity for this iid?
        user = self._node.db.get_identity(user_iid)
        if user is None:
            raise IdentityNotFoundError(user_iid)

        with self._Session() as session:
            # do we have an object with this id?
            record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
            if record is None:
                raise DataObjectNotFoundError(obj_id)

            # revoke access
            if user_iid in record.access:
                record.access.remove(user_iid)
            session.commit()

        return self.get_meta(obj_id)

    def transfer_ownership(self, obj_id: str, new_owner_iid: str) -> Union[CDataObject, GPPDataObject]:
        # do we have an identity for this iid?
        new_owner = self._node.db.get_identity(new_owner_iid)
        if new_owner is None:
            raise IdentityNotFoundError(new_owner_iid)

        with self._Session() as session:
            # do we have an object with this id?
            record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
            if record is None:
                raise DataObjectNotFoundError(obj_id)

            # transfer ownership
            record.owner_iid = new_owner_iid
            session.commit()

        return self.get_meta(obj_id)

    def update_tags(self, obj_id: str, tags: List[Tag]) -> Union[CDataObject, GPPDataObject]:
        with self._Session() as session:
            # do we have an object with this id?
            record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
            if record is None:
                raise DataObjectNotFoundError(obj_id)

            # update tags
            for tag in tags:
                record.tags[tag.key] = tag.value
            session.commit()

        return self.get_meta(obj_id)

    def remove_tags(self, obj_id: str, keys: List[str]) -> Union[CDataObject, GPPDataObject]:
        with self._Session() as session:
            # do we have an object with this id?
            record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
            if record is None:
                raise DataObjectNotFoundError(obj_id)

            # remove keys
            for key in keys:
                record.tags.pop(key, None)
            session.commit()

        return self.get_meta(obj_id)
