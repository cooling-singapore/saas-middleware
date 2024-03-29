from __future__ import annotations

import json
import os
import subprocess
import tempfile
from stat import S_IREAD, S_IRGRP
from threading import Lock
from typing import Optional, List, Union

import snappy
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from fastapi import UploadFile, File, Form
from fastapi.responses import FileResponse, StreamingResponse, Response
from sqlalchemy import Column, String, Boolean, BigInteger
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy_json import NestedMutableJson

from saas.core.helpers import hash_string_object, hash_json_object
from saas.dor.exceptions import CloneRepositoryError, CheckoutCommitError, ProcessorDescriptorNotFoundError, \
    InvalidProcessorDescriptorError, DataObjectContentNotFoundError, DataObjectNotFoundError, \
    DORException
from saas.dor.proxy import DORProxy, DOR_ENDPOINT_PREFIX
from saas.core.helpers import get_timestamp_now, generate_random_string, read_json_from_file, validate_json
from saas.core.logging import Logging
from saas.nodedb.exceptions import IdentityNotFoundError
from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.nodedb.schemas import NodeInfo
from saas.rest.auth import VerifyIsOwner, VerifyUserHasAccess
from saas.dor.schemas import DORStatistics, CObjectNode, DataObjectRecipe, DataObjectProvenance, DataObject, \
    GPPDataObject, CDataObject, ProcessorDescriptor, GPP_DATA_TYPE, GPP_DATA_FORMAT, SearchParameters, \
    AddCDataObjectParameters, AddGPPDataObjectParameters
from saas.core.schemas import GithubCredentials
from saas.rest.schemas import EndpointDefinition

logger = Logging.get('dor.service')

Base = declarative_base()

DOR_INFIX_MASTER_PATH = 'dor-master'
DOR_INFIX_TEMP_PATH = 'dor-temp'


def _generate_object_id(c_hash: str, data_type: str, data_format: str, creators_iid: List[str], created_t: int) -> str:
    # TODO: since timestamp is included the resulting object id is very much random -> consider replacing deriving
    #  object id based on hashing with generating actual random ids instead.
    return hash_string_object(f"{c_hash}{data_type}{data_format}{''.join(creators_iid)}{created_t}").hex()


def _generate_gpp_hash(source: str, commit_id: str, proc_path: str, proc_config: str, proc_descriptor: dict) -> str:
    return hash_json_object({
        'source': source,
        'commit_id': commit_id,
        'proc_path': proc_path,
        'proc_config': proc_config,
        'proc_descriptor': proc_descriptor
    }).hex()


def _generate_missing_provenance(c_hash: str, data_type: str, data_format: str) -> DataObjectProvenance:
    provenance = DataObjectProvenance.parse_obj({
        'data_nodes': {
            c_hash: CObjectNode.parse_obj({
                'c_hash': c_hash,
                'data_type': data_type,
                'data_format': data_format
            })
        },
        'proc_nodes': {},
        'steps': [],
        'missing': [c_hash]
    })
    return provenance


def _generate_by_value_provenance(c_hash: str, data_type: str, data_format: str, content: dict) -> DataObjectProvenance:
    provenance = DataObjectProvenance.parse_obj({
        'data_nodes': {
            c_hash: CObjectNode.parse_obj({
                'c_hash': c_hash,
                'data_type': data_type,
                'data_format': data_format,
                'content': content
            })
        },
        'proc_nodes': {},
        'steps': [],
        'missing': []
    })
    return provenance


def _extract_data_object(record: DataObjectRecord, custodian: NodeInfo) -> Union[CDataObject, GPPDataObject]:
    # is it a GPP data object?
    details = dict(record.details)
    created = dict(record.created)
    if record.data_type == GPP_DATA_TYPE:
        return GPPDataObject.parse_obj({
            'obj_id': record.obj_id,
            'c_hash': record.c_hash,
            'data_type': record.data_type,
            'data_format': record.data_format,
            'created': created,
            'owner_iid': record.owner_iid,
            'access_restricted': record.access_restricted,
            'access': record.access,
            'tags': record.tags,
            'last_accessed': record.last_accessed,
            'custodian': custodian,

            'gpp': {
                'source': details['source'],
                'commit_id': details['commit_id'],
                'proc_path': details['proc_path'],
                'proc_config': details['proc_config'],
                'proc_descriptor': details['proc_descriptor']
            }
        })

    else:
        return CDataObject.parse_obj({
            'obj_id': record.obj_id,
            'c_hash': record.c_hash,
            'data_type': record.data_type,
            'data_format': record.data_format,
            'created': created,
            'owner_iid': record.owner_iid,
            'access_restricted': record.access_restricted,
            'access': record.access,
            'tags': record.tags,
            'last_accessed': record.last_accessed,
            'custodian': custodian,

            'content_encrypted': details['content_encrypted'],
            'license': details['license'],
            'recipe': details['recipe'] if 'recipe' in details else None
        })


def fetch_proc_descriptor(source: str, commit_id: str, proc_path: str, proc_config: str,
                          credentials: GithubCredentials = None) -> ProcessorDescriptor:
    """
    Clone repo in gpp and returns the proc descriptor
    """
    # determine URL including credentials (if any)
    url = source
    if credentials:
        insert = f"{credentials.login}:{credentials.personal_access_token}@"
        index = url.find('github.com')
        url = url[:index] + insert + url[index:]

    # try to clone the repository
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = tmpdir
        result = subprocess.run(['git', 'clone', url, repo_path], capture_output=True)
        if result.returncode != 0:
            raise CloneRepositoryError({
                'url': url,
                'stdout': result.stdout.decode('utf-8'),
                'stderr': result.stderr.decode('utf-8')
            })

        # try to check out the specific commit
        result = subprocess.run(['git', 'checkout', commit_id], capture_output=True, cwd=repo_path)
        if result.returncode != 0:
            raise CheckoutCommitError({
                'commit_id': commit_id,
                'stdout': result.stdout.decode('utf-8'),
                'stderr': result.stderr.decode('utf-8')
            })

        # does the processor descriptor exist?
        proc_descriptor_path = os.path.join(repo_path, proc_path, 'descriptor.json')
        if not os.path.isfile(proc_descriptor_path):
            raise ProcessorDescriptorNotFoundError({
                'source': source,
                'commit_id': commit_id,
                'proc_path': proc_path
            })

        # read the processor descriptor
        proc_descriptor = read_json_from_file(proc_descriptor_path)
        if not validate_json(proc_descriptor, ProcessorDescriptor.schema()):
            raise InvalidProcessorDescriptorError({
                'source': source,
                'commit_id': commit_id,
                'proc_path': proc_path,
                'proc_descriptor': proc_descriptor
            })
        proc_descriptor = ProcessorDescriptor.parse_obj(proc_descriptor)

        # check if the config is valid
        if proc_config not in proc_descriptor.configurations:
            raise DORException(reason=f"Processor configuration '{proc_config}' not supported by processor.",
                               details={
                                   'proc_config': proc_config,
                                   'proc_descriptor': proc_descriptor.dict()
                               })
    return proc_descriptor


class DataObjectRecord(Base):
    __tablename__ = 'obj_record'
    obj_id = Column(String(64), primary_key=True)

    # immutable part of the meta information
    c_hash = Column(String(64), nullable=False)
    data_type = Column(String(64), nullable=False)
    data_format = Column(String(64), nullable=False)
    created = Column(NestedMutableJson, nullable=False)

    # mutable part of the meta information
    owner_iid = Column(String(64), nullable=False)
    access_restricted = Column(Boolean, nullable=False)
    access = Column(NestedMutableJson, nullable=False)
    tags = Column(NestedMutableJson, nullable=False)
    last_accessed = Column(BigInteger, nullable=False)

    # type-specific meta information
    details = Column(NestedMutableJson, nullable=False)


class DataObjectProvenanceRecord(Base):
    __tablename__ = 'obj_provenance'
    c_hash = Column(String(64), primary_key=True)
    p_hash = Column(String(64), primary_key=True)
    provenance = Column(NestedMutableJson, nullable=False)


class DORService:
    def __init__(self, node, db_path: str):
        # initialise properties
        self._db_mutex = Lock()
        self._node = node
        self._protocol = DataObjectRepositoryP2PProtocol(node)

        # initialise database things
        self._engine = create_engine(db_path)
        Base.metadata.create_all(self._engine)
        self._Session = sessionmaker(bind=self._engine)

        # initialise directories
        os.makedirs(os.path.join(self._node.datastore, DOR_INFIX_MASTER_PATH), exist_ok=True)
        os.makedirs(os.path.join(self._node.datastore, DOR_INFIX_TEMP_PATH), exist_ok=True)

    @property
    def protocol(self) -> DataObjectRepositoryP2PProtocol:
        return self._protocol

    def obj_content_path(self, c_hash: str) -> str:
        return os.path.join(self._node.datastore, DOR_INFIX_MASTER_PATH, c_hash)

    def _add_provenance_record(self, c_hash: str, provenance: dict) -> None:
        with self._db_mutex:
            with self._Session() as session:
                # determine provenance hash and see if we already have that in the database. if not, add a db record.
                p_hash = hash_json_object(provenance).hex()
                record = session.query(DataObjectProvenanceRecord).filter_by(p_hash=p_hash).first()
                if record is None:
                    session.add(DataObjectProvenanceRecord(c_hash=c_hash, p_hash=p_hash, provenance=provenance))
                    session.commit()
                    logger.info(f"database provenance record created for c_hash={c_hash} and p_hash={p_hash}.")
                else:
                    logger.info(f"database provenance record already exists for c_hash={c_hash} and p_hash={p_hash}.")

    def _search_network_for_provenance(self, c_hash: str) -> List[DataObjectProvenance]:
        # check every node in the network for provenance information
        result = []
        for node in self._node.db.get_network():
            if node.dor_service and node.rest_address is not None:
                dor = DORProxy(node.rest_address)
                provenance = dor.get_provenance(c_hash)
                if provenance is not None:
                    # TODO: change once proxy has been refactored
                    result.append(DataObjectProvenance.parse_obj(provenance))
        return result

    def _generate_provenance_information(self, c_hash: str, recipe: DataObjectRecipe) -> DataObjectProvenance:
        data_nodes = {}
        proc_nodes = {}
        steps = []
        missing = []

        # handle the product
        product_node = CObjectNode(
            c_hash=c_hash,
            data_type=recipe.product.data_type,
            data_format=recipe.product.data_format
        )
        data_nodes[product_node.c_hash] = product_node

        # construct the step
        step = {
            'processor': None,
            'consumes': {},
            'produces': {
                recipe.name: product_node.c_hash
            }
        }

        # get provenance information for all the input data objects
        for name, obj in recipe.consumes.items():
            # is it a by-reference object
            if obj.content is None:
                # search the network for provenance information. if there are multiple provenance instances (unlikely
                # but not impossible), just use the first one.
                # TODO: this behaviour should possibly be improved at some point
                provenance = self._search_network_for_provenance(obj.c_hash)
                provenance = provenance[0] if len(provenance) > 0 else None

                # is the provenance information missing?
                if provenance is None:
                    provenance = _generate_missing_provenance(obj.c_hash, obj.data_type, obj.data_format)
                    missing.append(obj.c_hash)

                # add to step
                step['consumes'][name] = obj.c_hash

                # merge dicts
                data_nodes.update(provenance.data_nodes)
                proc_nodes.update(provenance.proc_nodes)
                steps += provenance.steps
                missing += provenance.missing

            else:
                # by-value objects are not uploaded to the DOR, so their provenance information is not generated
                # when adding a data object to the DOR. let's generate provenance information for this by-value
                # object on the fly
                provenance = _generate_by_value_provenance(obj.c_hash, obj.data_type, obj.data_format, obj.content)
                self._add_provenance_record(obj.c_hash, provenance.dict())

                # add to step
                step['consumes'][name] = obj.c_hash

                # get the object node
                obj_node = provenance.data_nodes[obj.c_hash]
                data_nodes[obj.c_hash] = obj_node

        # calculate c_hash for processor and keep the GPP in the dict that keeps all unique processors involved
        step['processor'] = _generate_gpp_hash(recipe.processor.source, recipe.processor.commit_id,
                                               recipe.processor.proc_path, recipe.processor.proc_config,
                                               recipe.processor.proc_descriptor.dict())
        if step['processor'] not in proc_nodes:
            proc_nodes[step['processor']] = recipe.processor

        # add the step
        steps.append(step)

        provenance = DataObjectProvenance(
            data_nodes=data_nodes,
            proc_nodes=proc_nodes,
            steps=steps,
            missing=missing
        )

        return provenance

    def endpoints(self) -> List[EndpointDefinition]:
        return [
            EndpointDefinition('GET', DOR_ENDPOINT_PREFIX, '',
                               self.search, List[Union[CDataObject, GPPDataObject]], None),

            EndpointDefinition('GET', DOR_ENDPOINT_PREFIX, 'statistics',
                               self.statistics, DORStatistics, None),

            EndpointDefinition('POST', DOR_ENDPOINT_PREFIX, 'add-c',
                               self.add_c, CDataObject, None),

            EndpointDefinition('POST', DOR_ENDPOINT_PREFIX, 'add-gpp',
                               self.add_gpp, GPPDataObject, None),

            EndpointDefinition('DELETE', DOR_ENDPOINT_PREFIX, '{obj_id}',
                               self.remove, Union[CDataObject, GPPDataObject], [VerifyIsOwner]),

            EndpointDefinition('GET', DOR_ENDPOINT_PREFIX, '{obj_id}/meta',
                               self.get_meta, Optional[Union[CDataObject, GPPDataObject]], None),

            EndpointDefinition('GET', DOR_ENDPOINT_PREFIX, '{obj_id}/content',
                               self.get_content, None, [VerifyUserHasAccess]),

            EndpointDefinition('GET', DOR_ENDPOINT_PREFIX, '{c_hash}/provenance',
                               self.get_provenance, Optional[DataObjectProvenance], None),

            EndpointDefinition('POST', DOR_ENDPOINT_PREFIX, '{obj_id}/access/{user_iid}',
                               self.grant_access, Union[CDataObject, GPPDataObject], [VerifyIsOwner]),

            EndpointDefinition('DELETE', DOR_ENDPOINT_PREFIX, '{obj_id}/access/{user_iid}',
                               self.revoke_access, Union[CDataObject, GPPDataObject], [VerifyIsOwner]),

            EndpointDefinition('PUT', DOR_ENDPOINT_PREFIX, '{obj_id}/owner/{new_owner_iid}',
                               self.transfer_ownership, Union[CDataObject, GPPDataObject], [VerifyIsOwner]),

            EndpointDefinition('PUT', DOR_ENDPOINT_PREFIX, '{obj_id}/tags',
                               self.update_tags, Union[CDataObject, GPPDataObject],
                               [VerifyIsOwner]),

            EndpointDefinition('DELETE', DOR_ENDPOINT_PREFIX, '{obj_id}/tags',
                               self.remove_tags, Union[CDataObject, GPPDataObject], [VerifyIsOwner])
        ]

    def search(self, p: SearchParameters) -> List[Union[CDataObject, GPPDataObject]]:
        """
        Searches a DOR for data objects that match the search criteria. There are two kinds of criteria: constraints
        and patterns. Search constraints are conjunctive, i.e., all constraints have to be matched in order for a data
        objective to be considered for inclusion in the search result. Constraints include: `owner_iid`, `data_type`,
        `data_format` or list of `c_hashes`. After applying the search constraints, the result set is further filtered
        by the search patterns. Unlike constraints, search patterns are disjunctive, i.e., so long as any of the
        patterns is matched, the data object is included in the final result set. Search patterns are applied to the
        data object tags only. A search pattern is considered matched if it is a substring of either tag key or value.
        """
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
                flattened = ' '.\
                    join(f"{key} {json.dumps(value) if isinstance(value, (list, dict)) else value}"
                         for key, value in record.tags.items())

                # check if any of the patterns is a substring the flattened string.
                # if we don't have patterns then always add the object.
                if p.patterns is None or any(pattern in flattened for pattern in p.patterns):
                    # convert into an C/GPP data object and add to the result
                    result.append(_extract_data_object(record, self._node.info))

            return result

    def statistics(self) -> DORStatistics:
        """
        Retrieves some statistics from the DOR. This includes a list of all data types and formats found in the DOR.
        """
        with self._Session() as session:
            return DORStatistics(
                data_types=[value[0] for value in session.query(DataObjectRecord.data_type).distinct()],
                data_formats=[value[0] for value in session.query(DataObjectRecord.data_format).distinct()]
            )

    def add_c(self, body: str = Form(...), attachment: UploadFile = File(...)) -> CDataObject:
        """
        Adds a new content data object to the DOR and returns the meta information for this data object. The content
        of the data object itself is uploaded as an attachment (binary). There is no restriction as to the nature or
        size of the content.
        """
        # create parameters object
        p = AddCDataObjectParameters.parse_obj(json.loads(body))

        # get the owner identity
        owner = self._node.db.get_identity(p.owner_iid, raise_if_unknown=True)

        # check if we know the creator identities
        # TODO: decide whether or not to remove this check. removing it allows to use creator ids that the
        #  node isn't aware of.
        for creator_iid in p.creators_iid:
            self._node.db.get_identity(creator_iid, raise_if_unknown=True)

        # temp file for attachment
        attachment_path = os.path.join(self.obj_content_path(f"{get_timestamp_now()}_{generate_random_string(4)}"))
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        try:
            with open(attachment_path, 'wb') as f:
                buffer = bytearray()
                while True:
                    chunk = attachment.file.read(4)
                    if not chunk:
                        break

                    chunk_length = int.from_bytes(chunk, 'big')
                    chunk = attachment.file.read(chunk_length)
                    chunk = snappy.decompress(chunk)
                    buffer.extend(chunk)
                    digest.update(chunk)
                    f.write(chunk)

        except Exception as e:
            raise DORException("upload failed", details={'exception': e})

        finally:
            attachment.file.close()

        # calculate the hash for the data object content
        c_hash = digest.finalize().hex()

        # fix the c_hash in the recipe (if any)
        if p.recipe:
            p.recipe.product.c_hash = c_hash

        # determine the object id
        created_t = get_timestamp_now()
        obj_id = _generate_object_id(c_hash, p.data_type, p.data_format, p.creators_iid, created_t)

        with self._db_mutex:
            with self._Session() as session:
                # check if there are already data objects with the same content (i.e., referencing the same c_hash).
                # it is possible for cases like this to happen. despite the exact same content, this may well be
                # a legitimate different data object. for example, different provenance has led to the exact same
                # outcome. we thus create a new data object.
                records = session.query(DataObjectRecord).filter_by(c_hash=c_hash).all()
                if len(records) > 0:
                    # delete the temporary content as it is not needed
                    os.remove(attachment_path)

                else:
                    # move the temporary content to its destination and make it read-only
                    destination_path = self.obj_content_path(c_hash)
                    os.rename(attachment_path, destination_path)
                    os.chmod(destination_path, S_IREAD | S_IRGRP)

                # create a new data object record
                session.add(DataObjectRecord(obj_id=obj_id, c_hash=c_hash,
                                             data_type=p.data_type, data_format=p.data_format,
                                             created={
                                                 'timestamp': created_t,
                                                 'creators_iid': p.creators_iid
                                             },
                                             owner_iid=owner.id, access_restricted=p.access_restricted,
                                             access=[owner.id], tags={},
                                             details={
                                                 'content_encrypted': p.content_encrypted,
                                                 'license': p.license.dict(),
                                                 'recipe': p.recipe.dict() if p.recipe else None,
                                             },
                                             last_accessed=created_t))
                session.commit()
                logger.info(f"data object '{obj_id}' with content '{c_hash}' added to DOR. the content is "
                            f"referenced by {len(records)} other data objects).")

        # determine the provenance and add to the database
        provenance = self._generate_provenance_information(c_hash, p.recipe) if p.recipe else \
            _generate_missing_provenance(c_hash, p.data_type, p.data_format)
        self._add_provenance_record(c_hash, provenance.dict())

        return self.get_meta(obj_id)

    def add_gpp(self, p: AddGPPDataObjectParameters) -> GPPDataObject:
        """
        Adds a Git-Processor-Pointer (GPP) data object to the DOR and returns the meta information for this data object.
        If the repository specified in the GPP information is private, valid  credentials need to be provided. The DOR
        will use these credentials to access (i.e., clone) the repository. Note that the credentials information will
        not be stored by the DOR.
        """
        # get the owner and creator identity
        owner = self._node.db.get_identity(p.owner_iid, raise_if_unknown=True)

        # check if we know the creator identities
        # TODO: decide whether or not to remove this check. removing it allows to use creator ids that the
        #  node isn't aware of.
        for creator_iid in p.creators_iid:
            self._node.db.get_identity(creator_iid, raise_if_unknown=True)

        # fetch proc descriptor
        proc_descriptor = fetch_proc_descriptor(p.source, p.commit_id, p.proc_path, p.proc_config, p.github_credentials)

        # determine the content hash for the GPP
        c_hash = _generate_gpp_hash(p.source, p.commit_id, p.proc_path, p.proc_config, proc_descriptor.dict())

        # determine the object id (in case of a GPP, it's simply the content hash)
        obj_id = c_hash

        with self._db_mutex:
            with self._Session() as session:
                # do we already have a record for this GPP?
                if session.query(DataObjectRecord).get(obj_id) is not None:
                    logger.info(f"GPP object '{obj_id}' already exists -> not adding.")

                else:
                    logger.info(f"GPP object '{obj_id}' does not exist -> adding.")

                    # add a new data object record
                    created_t = get_timestamp_now()
                    session.add(DataObjectRecord(obj_id=obj_id, c_hash=c_hash,
                                                 data_type=GPP_DATA_TYPE, data_format=GPP_DATA_FORMAT,
                                                 created={
                                                     'timestamp': created_t,
                                                     'creators_iid': p.creators_iid
                                                 },
                                                 owner_iid=owner.id, access_restricted=False, access=[owner.id],
                                                 tags={},
                                                 details={
                                                     'source': p.source,
                                                     'commit_id': p.commit_id,
                                                     'proc_path': p.proc_path,
                                                     'proc_config': p.proc_config,
                                                     'proc_descriptor': proc_descriptor.dict()
                                                 },
                                                 last_accessed=created_t))

                    session.commit()

        return self.get_meta(obj_id)

    def remove(self, obj_id: str) -> Optional[Union[CDataObject, GPPDataObject]]:
        """
        Deletes a data object from the DOR and returns the meta information of that data object. Authorisation by the
        data object owner is required.
        """
        # get the meta information for this object (if it exists in the first place)
        meta = self.get_meta(obj_id)
        if meta is None:
            return None

        # delete the data object
        with self._db_mutex:
            with self._Session() as session:
                # delete the database record only (we do not delete the provenance information)
                session.query(DataObjectRecord).filter_by(obj_id=obj_id).delete()
                session.commit()

        # is it a C data object?
        if meta.data_type != GPP_DATA_TYPE:
            # if it's a content data object, we need to check if there are other data objects that point to the same
            # content (unlikely but not impossible).
            with self._db_mutex:
                with self._Session() as session:
                    referenced = session.query(DataObjectRecord).filter_by(c_hash=meta.c_hash).all()
                    referenced = [record.obj_id for record in referenced]

            # only delete if we have not found any other data objects that reference this content.
            if len(referenced) == 0:
                logger.info(f"data object content '{meta.c_hash}' not referenced by any data object -> delete.")
                content_path = self.obj_content_path(meta.c_hash)
                os.remove(content_path)
            else:
                logger.info(f"data object content '{meta.c_hash}' referenced by data objects ({referenced}) -> "
                            f"do not delete.")

        return meta

    def get_meta(self, obj_id: str) -> Optional[Union[CDataObject, GPPDataObject]]:
        """
        Retrieves the meta information of a data object. Depending on the type of the data object, either a
        `CDataObject` or a `GPPDataObject` is returned, providing meta information for content and GPP data objects,
        respectively.
        """
        with self._Session() as session:
            # do we have an object with this id?
            record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
            if record is None:
                return None

            # is it a GPP data object?
            return _extract_data_object(record, self._node.info)

    def get_content(self, obj_id: str) -> Response:
        """
        Retrieves the content of a data object. Authorisation required by a user who has been granted access to the
        data object.
        """
        # get the meta information for this object (if it exists in the first place)
        meta = self.get_meta(obj_id)
        if meta is None:
            raise DataObjectNotFoundError(obj_id)

        # is it a GPP
        if meta.data_type == GPP_DATA_TYPE:
            async def gpp_streamer():
                yield json.dumps(meta.gpp.dict(), indent=4).encode('utf-8')

            return StreamingResponse(
                content=gpp_streamer(),
                media_type='application/octet-stream'
            )

        else:
            # check if we have the content
            content_path = self.obj_content_path(meta.c_hash)
            if not os.path.isfile(content_path):
                raise DataObjectContentNotFoundError({
                    'path': content_path
                })

            # touch data object
            self.touch_data_object(obj_id)

            return FileResponse(content_path, media_type='application/octet-stream')

    def get_provenance(self, c_hash: str) -> Optional[DataObjectProvenance]:
        """
        Retrieves the provenance information of a data object (identified by its content hash `c_hash`). Provenance
        data includes detailed information how the content of a data object has been produced. In principle, this
        information enables users to reproduce the contents by repeating the exact same steps. Note that it is possible
        that there are multiple routes by which a content can be generated. Depending on the use case, this kind of
        situation is likely to be rare. However, careful analysis of the provenance information might be needed to
        understand how the content has been created.
        """
        with self._Session() as session:
            # do we have an object with this id?
            records: list[DataObjectProvenanceRecord] = session.query(DataObjectProvenanceRecord).filter(
                (DataObjectProvenanceRecord.c_hash == c_hash)).all()
            return DataObjectProvenance.parse_obj(records[0].provenance) if records else None

    def grant_access(self, obj_id: str, user_iid: str) -> Union[CDataObject, GPPDataObject]:
        """
        Grants a user the right to access the contents of a restricted data object. Authorisation required by the owner
        of the data object. Note that access rights only matter if the data object has access restrictions.
        """
        # do we have an identity for this iid?
        user = self._node.db.get_identity(user_iid)
        if user is None:
            raise IdentityNotFoundError(user_iid)

        with self._db_mutex:
            with self._Session() as session:
                # do we have an object with this id?
                record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
                if record is None:
                    raise DataObjectNotFoundError(obj_id)

                # grant access
                if user_iid not in record.access:
                    record.access.append(user_iid)
                    session.commit()

        # touch data object
        self.touch_data_object(obj_id)

        return self.get_meta(obj_id)

    def revoke_access(self, obj_id: str, user_iid: str) -> Union[CDataObject, GPPDataObject]:
        """
        Revokes the right to access the contents of a restricted data object from a user. Authorisation required by the
        owner of the data object. Note that access rights only matter if the data object has access restrictions.
        """
        # do we have an identity for this iid?
        user = self._node.db.get_identity(user_iid)
        if user is None:
            raise IdentityNotFoundError(user_iid)

        with self._db_mutex:
            with self._Session() as session:
                # do we have an object with this id?
                record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
                if record is None:
                    raise DataObjectNotFoundError(obj_id)

                # revoke access
                if user_iid in record.access:
                    record.access.remove(user_iid)
                session.commit()

        # touch data object
        self.touch_data_object(obj_id)

        return self.get_meta(obj_id)

    def transfer_ownership(self, obj_id: str, new_owner_iid: str) -> Union[CDataObject, GPPDataObject]:
        """
        Transfers the ownership of a data object to another user. Authorisation required by the current owner of the
        data object.
        """
        # do we have an identity for this iid?
        new_owner = self._node.db.get_identity(new_owner_iid)
        if new_owner is None:
            raise IdentityNotFoundError(new_owner_iid)

        with self._db_mutex:
            with self._Session() as session:
                # do we have an object with this id?
                record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
                if record is None:
                    raise DataObjectNotFoundError(obj_id)

                # transfer ownership
                record.owner_iid = new_owner_iid
                session.commit()

        # touch data object
        self.touch_data_object(obj_id)

        return self.get_meta(obj_id)

    def update_tags(self, obj_id: str, tags: List[DataObject.Tag]) -> Union[CDataObject, GPPDataObject]:
        """
        Adds tags to a data object or updates tags in case they already exist. Authorisation required by the owner of
        the data object.
        """
        with self._db_mutex:
            with self._Session() as session:
                # do we have an object with this id?
                record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
                if record is None:
                    raise DataObjectNotFoundError(obj_id)

                # update tags
                for tag in tags:
                    record.tags[tag.key] = tag.value if tag.value else None
                session.commit()

        # touch data object
        self.touch_data_object(obj_id)

        return self.get_meta(obj_id)

    def remove_tags(self, obj_id: str, keys: List[str]) -> Union[CDataObject, GPPDataObject]:
        """
        Removes tags from a data object. Authorisation required by the owner of the data object.
        """
        with self._db_mutex:
            with self._Session() as session:
                # do we have an object with this id?
                record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
                if record is None:
                    raise DataObjectNotFoundError(obj_id)

                # remove keys
                for key in keys:
                    record.tags.pop(key, None)
                session.commit()

        # touch data object
        self.touch_data_object(obj_id)

        return self.get_meta(obj_id)

    def touch_data_object(self, obj_id) -> None:
        with self._db_mutex:
            with self._Session() as session:
                # do we have an object with this id?
                record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
                if record is None:
                    raise DataObjectNotFoundError(obj_id)

                # update the last accessed timestamp of this data object
                record: DataObjectRecord = session.query(DataObjectRecord).get(obj_id)
                record.last_accessed = get_timestamp_now()
                session.commit()
