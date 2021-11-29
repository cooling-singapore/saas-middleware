import json
from dataclasses import dataclass, asdict
from typing import Optional, Union

import canonicaljson
from sqlalchemy import Column, String, BigInteger, Integer, Boolean, Text, Table
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, registry

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.helpers import hash_json_object, hash_string_object
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.helpers import get_timestamp_now
from saas.keystore.identity import Identity
from saas.logging import Logging
from saas.nodedb.exceptions import DataObjectNotFoundError, InvalidIdentityError

logger = Logging.get('nodedb.service')

mapper_registry = registry()
Base = mapper_registry.generate_base()


@mapper_registry.mapped
@dataclass
class DataObjectRecord:
    __table__ = Table(
        'obj_record',
        mapper_registry.metadata,

        Column("obj_id", String(64), primary_key=True),

        Column("c_hash", String(64), nullable=False),
        Column("data_type", String(64), nullable=False),
        Column("data_format", String(64), nullable=False),
        Column("created_by", String(64), nullable=False),
        Column("created_t", Integer, nullable=False),
        Column("gpp", Text, nullable=True),

        Column("owner_iid", String(64), nullable=False),
        Column("access_restricted", Boolean, nullable=False),
        Column("content_encrypted", Boolean, nullable=False)
    )

    obj_id: str

    # IMMUTABLE part of meta information:
    c_hash: str
    data_type: str
    data_format: str
    created_by: str
    created_t: int
    gpp: Optional[str]

    # MUTABLE part of meta information:
    owner_iid: str
    access_restricted: bool
    content_encrypted: bool


@mapper_registry.mapped
@dataclass
class DataObjectRecipe:
    __table__ = Table(
        'obj_recipe',
        mapper_registry.metadata,
        Column("c_hash", String(64), primary_key=True),
        Column("r_hash", String(64), primary_key=True),
        Column("recipe", Text, nullable=False)
    )

    c_hash: str
    r_hash: str
    recipe: str


@mapper_registry.mapped
@dataclass
class DataObjectTag:
    __table__ = Table(
        'obj_tag',
        mapper_registry.metadata,
        Column("obj_id", String(64), primary_key=True),
        Column("key", String(64), primary_key=True),
        Column("value", String(256))
    )

    obj_id: str
    key: str
    value: str


@mapper_registry.mapped
@dataclass
class DataObjectAccess:
    __table__ = Table(
        'obj_access',
        mapper_registry.metadata,
        Column("obj_id", String(64), primary_key=True),
        Column("key_iid", String(64), primary_key=True)
    )

    obj_id: str
    key_iid: str


@mapper_registry.mapped
@dataclass
class IdentityRecord:
    __table__ = Table(
        'identity',
        mapper_registry.metadata,
        Column("iid", String(64), primary_key=True),
        Column("name", String, nullable=False),
        Column("email", String, nullable=False),
        Column("nonce", Integer, nullable=False),
        Column("s_public_key", String, nullable=True),
        Column("e_public_key", String, nullable=True),
        Column("signature", String, nullable=True)
    )

    iid: str
    name: str
    email: str
    nonce: int
    s_public_key: Optional[str]
    e_public_key: Optional[str]
    signature: Optional[str]


@mapper_registry.mapped
@dataclass
class NetworkNode:
    __table__ = Table(
        'network_node',
        mapper_registry.metadata,
        Column("iid", String(64), primary_key=True),
        Column("last_seen", BigInteger, nullable=False),
        Column("p2p_address", String(21), nullable=False),
        Column("rest_address", String(21), nullable=True),
        Column("dor_service", Boolean, nullable=False),
        Column("rti_service", Boolean, nullable=False)
    )

    iid: str
    last_seen: int
    p2p_address: str
    rest_address: Optional[str]
    dor_service: bool
    rti_service: bool

    def get_p2p_address(self):
        return self.p2p_address.split(":")

    def get_rest_address(self) -> (str, str):
        return self.rest_address.split(':') if self.rest_address else None

    def asdict(self) -> dict:
        return asdict(self, dict_factory=lambda x: {k: v for (k, v) in x if v is not None})


class NodeDBService:
    def __init__(self, node, db_path, protocol):
        self._node = node
        self.protocol = protocol
        self._engine = create_engine(db_path)
        Base.metadata.create_all(self._engine)
        self._Session = sessionmaker(bind=self._engine)

        self._print_statistics()

    def _print_statistics(self):
        with self._Session() as session:
            logger.debug(f"- DataObjectRecord: {session.query(DataObjectRecord).count()}")
            logger.debug(f"- DataObjectRecipe: {session.query(DataObjectRecipe).count()}")
            logger.debug(f"- DataObjectTag: {session.query(DataObjectTag).count()}")
            logger.debug(f"- DataObjectAccess: {session.query(DataObjectAccess).count()}")
            logger.debug(f"- IdentityRecord: {session.query(IdentityRecord).count()}")
            logger.debug(f"- NetworkNode: {session.query(NetworkNode).count()}")

    def _require_data_object(self, obj_id: str) -> DataObjectRecord:
        with self._Session() as session:
            obj_record = session.query(DataObjectRecord).get(obj_id)
            if obj_record is None:
                raise DataObjectNotFoundError({
                    'obj_id': obj_id
                })
            return obj_record

    # BEGIN: things that do NOT require synchronisation

    def update_tags(self, obj_id: str, tags: list[dict[str, str]]) -> None:
        self._require_data_object(obj_id)
        with self._Session() as session:
            # update the tags
            for tag in tags:
                item = session.query(DataObjectTag).filter_by(obj_id=obj_id, key=tag['key']).first()
                if item:
                    item.value = tag['value']
                else:
                    session.add(DataObjectTag(obj_id=obj_id, key=tag['key'], value=tag['value']))
            session.commit()

    def remove_tags(self, obj_id: str, keys: list[str] = None) -> None:
        self._require_data_object(obj_id)
        with self._Session() as session:
            # remove specific tags
            if keys:
                for key in keys:
                    session.query(DataObjectTag).filter_by(obj_id=obj_id, key=key).delete()

            # remove all tags
            else:
                session.query(DataObjectTag).filter_by(obj_id=obj_id).delete()

            session.commit()

    def get_statistics(self) -> dict:
        with self._Session() as session:
            test = session.query(DataObjectRecord.data_type).distinct()
            result = {
                'data_types': [value[0] for value in session.query(DataObjectRecord.data_type).distinct()],
                'data_formats': [value[0] for value in session.query(DataObjectRecord.data_format).distinct()],
                'tag_keys': sorted([value[0] for value in session.query(DataObjectTag.key).distinct()])
            }

            return result

    def find_data_objects(self, patterns: list[str], owner_iid: str = None,
                          data_type: str = None, data_format: str = None,
                          c_hashes: list[str] = None) -> list[dict]:
        with self._Session() as session:
            # build the query and get the results
            q = session.query(DataObjectRecord).filter()
            if owner_iid is not None:
                q = q.filter(DataObjectRecord.owner_iid == owner_iid)

            if data_type is not None:
                q = q.filter(DataObjectRecord.data_type == data_type)

            if data_format is not None:
                q = q.filter(DataObjectRecord.data_format == data_format)

            if c_hashes is not None:
                q = q.filter(DataObjectRecord.c_hash.in_(c_hashes))

            object_records = q.all()

            # second, filter data objects by patterns (if any)
            result = []
            for obj_record in object_records:
                # prepare a tags array for the result dict
                tag_records = session.query(DataObjectTag).filter_by(obj_id=obj_record.obj_id).all()
                tags = [{'key': tag.key, 'value': tag.value} for tag in tag_records]

                # flatten all tags (keys values) into a single string for search purposes
                flattened = ' '.join(f"{tag['key']} {tag['value']}" for tag in tags)

                # add meta information to make them searchable
                flattened += f" {obj_record.data_type}"
                flattened += f" {obj_record.data_format}"

                # check if any of the patterns is a substring the flattened string.
                # if we don't have patterns then always add the object.
                if patterns is None or any(pattern in flattened for pattern in patterns):
                    access = session.query(DataObjectAccess).filter_by(obj_id=obj_record.obj_id).all()

                    result.append({
                        'obj_id': obj_record.obj_id,
                        'c_hash': obj_record.c_hash,
                        'data_type': obj_record.data_type,
                        'data_format': obj_record.data_format,
                        'created_by': obj_record.created_by,
                        'created_t': obj_record.created_t,
                        'owner_iid': obj_record.owner_iid,
                        'access_restricted': obj_record.access_restricted,
                        'content_encrypted': obj_record.content_encrypted,
                        'tags': tags,
                        'access': [record.key_iid for record in access]
                    })

            return result

    def has_access(self, obj_id: str, identity: Identity) -> bool:
        self._require_data_object(obj_id)
        with self._Session() as session:
            return session.query(DataObjectAccess).filter_by(obj_id=obj_id, key_iid=identity.id).first() is not None

    def grant_access(self, obj_id: str, identity: Identity) -> None:
        self._require_data_object(obj_id)
        with self._Session() as session:
            # grant access (if it hasn't already been granted)
            item = session.query(DataObjectAccess).filter_by(obj_id=obj_id, key_iid=identity.id).first()
            if item is None:
                session.add(DataObjectAccess(obj_id=obj_id, key_iid=identity.id))
                session.commit()

    def revoke_access(self, obj_id: str, identity: Identity = None) -> list[str]:
        self._require_data_object(obj_id)
        with self._Session() as session:
            # query for all or a specific identity
            q = session.query(DataObjectAccess).filter_by(obj_id=obj_id, key_iid=identity.id) if identity else \
                session.query(DataObjectAccess).filter_by(obj_id=obj_id)

            # determine the ids of identities that have their access revoked
            result = [record.key_iid for record in q.all()]

            # revoke access
            q.delete()
            session.commit()

            return result

    def add_data_object(self, c_hash: str, data_type: str, data_format: str, created_by: str,
                        gpp: Optional[dict], owner: Identity, access_restricted: bool, content_encrypted: bool) -> dict:

        with self._Session() as session:
            created_t = get_timestamp_now()

            # determine object id
            gpp_hash = hash_json_object(gpp).hex() if gpp else ''
            obj_id = hash_string_object(f"{c_hash}{data_type}{data_format}{created_by}{created_t}{gpp_hash}").hex()

            # add a new data object record
            session.add(DataObjectRecord(obj_id=obj_id, c_hash=c_hash, data_type=data_type, data_format=data_format,
                                         created_by=created_by, created_t=created_t,
                                         gpp=json.dumps(gpp) if gpp else None,
                                         owner_iid=owner.id, access_restricted=access_restricted,
                                         content_encrypted=content_encrypted))

            # grant access permission to the owner
            session.add(DataObjectAccess(obj_id=obj_id, key_iid=owner.id))

            session.commit()

        return self.get_object_by_id(obj_id)

    def remove_data_object(self, obj_id: str) -> dict:
        self._require_data_object(obj_id)
        with self._Session() as session:
            record = self.get_object_by_id(obj_id)

            # remove the record, all tags and all access
            session.query(DataObjectRecord).filter_by(obj_id=obj_id).delete()
            session.query(DataObjectTag).filter_by(obj_id=obj_id).delete()
            session.query(DataObjectAccess).filter_by(obj_id=obj_id).delete()
            session.commit()

            return record

    def get_object_by_id(self, obj_id: str) -> Optional[dict]:
        with self._Session() as session:
            # do we have an object with this id?
            record = session.query(DataObjectRecord).get(obj_id)
            if record is None:
                return None

            # get all tags
            tags = session.query(DataObjectTag).filter_by(obj_id=obj_id).all()

            # get list of all identities that have access
            access = session.query(DataObjectAccess).filter_by(obj_id=obj_id).all()

            # prepare the data object information
            result = {
                'obj_id': record.obj_id,
                'c_hash': record.c_hash,
                'data_type': record.data_type,
                'data_format': record.data_format,
                'created_by': record.created_by,
                'created_t': record.created_t,
                'owner_iid': record.owner_iid,
                'access_restricted': record.access_restricted,
                'content_encrypted': record.content_encrypted,
                'tags': [{'key': tag.key, 'value': tag.value} for tag in tags],
                'access': [record.key_iid for record in access]
            }

            if record.gpp is not None:
                result['gpp'] = json.loads(record.gpp)

            return result

    def get_objects_by_content_hash(self, c_hash: str) -> list[dict]:
        with self._Session() as session:
            records = session.query(DataObjectRecord).filter_by(c_hash=c_hash).all()
            return [self.get_object_by_id(record.obj_id) for record in records]

    def get_owner(self, obj_id: str) -> Identity:
        record = self._require_data_object(obj_id)
        return self.get_identity(record.owner_iid)

    def update_ownership(self, obj_id: str, new_owner: Identity) -> None:
        self._require_data_object(obj_id)
        with self._Session() as session:
            # does the data object exist?
            obj_record = session.query(DataObjectRecord).get(obj_id)
            if obj_record is None:
                raise DataObjectNotFoundError({
                    'obj_id': obj_id
                })

            # transfer of ownership between same identities? --> nothing to do here.
            prev_owner = self.get_identity(obj_record.owner_iid)
            if prev_owner.id == new_owner.id:
                return

            # update ownership
            obj_record.owner_iid = new_owner.id
            session.commit()

        # revoke all access to this data object
        self.revoke_access(obj_id)

        # grant access to the new owner
        self.grant_access(obj_id, new_owner)

    # END: things that do NOT require synchronisation

    # BEGIN: things that DO require synchronisation

    def get_identity(self, iid: str = None) -> Optional[Identity]:
        with self._Session() as session:
            record = session.query(IdentityRecord).filter_by(iid=iid).first()
            return Identity(record.iid, record.name, record.email,
                            ECKeyPair.from_public_key_string(record.s_public_key) if record.s_public_key else None,
                            RSAKeyPair.from_public_key_string(record.e_public_key) if record.e_public_key else None,
                            record.nonce, record.signature) if record else None

    def get_all_identities(self) -> dict[str, Identity]:
        with self._Session() as session:
            records = session.query(IdentityRecord).all()
            return {record.iid: Identity(record.iid, record.name, record.email,
                                         ECKeyPair.from_public_key_string(record.s_public_key),
                                         RSAKeyPair.from_public_key_string(record.e_public_key),
                                         record.nonce, record.signature) for record in records}

    def update_identity(self, identity: Union[Identity, dict]) -> None:
        # deserialise the identity (if necessary) and verify its authenticity
        identity = Identity.deserialise(identity) if not isinstance(identity, Identity) else identity
        if not identity.is_authentic():
            raise InvalidIdentityError({
                'identity': identity
            })

        # update the db
        with self._Session() as session:
            # do we have the identity already on record?
            # only perform update if either the record does not exist yet OR if the information provided is valid
            # and more recent, i.e., if the nonce is greater than the one on record.
            record = session.query(IdentityRecord).filter_by(iid=identity.id).first()
            if record is None:
                session.add(IdentityRecord(iid=identity.id, name=identity.name, email=identity.email,
                                           s_public_key=identity.s_public_key_as_string(),
                                           e_public_key=identity.e_public_key_as_string(),
                                           nonce=identity.nonce, signature=identity.signature))
                session.commit()

            elif identity.nonce > record.nonce:
                record.name = identity.name
                record.email = identity.email
                record.nonce = identity.nonce
                record.s_key = identity.s_public_key_as_string()
                record.e_key = identity.e_public_key_as_string()
                record.signature = identity.signature
                session.commit()

            else:
                logger.debug("Ignore identity update as nonce on record is more recent.")

    def update_network(self, node_iid: str, last_seen: int, dor_service: bool, rti_service: bool,
                       p2p_address: (str, int), rest_address: (str, int) = None) -> None:
        with self._Session() as session:
            # TRACE: usefule for debugging
            # network = session.query(NetworkNode).all()
            # for record in network:
            #     print(f"R: {record.iid} {record.p2p_address} {record.rest_address} {record.last_seen}")
            # print(f"+: {node_iid} {p2p_address} {rest_address} {last_seen}")
            # print()

            # do we have conflicting records (i.e., records of a node with a different iid but on the same P2P/REST
            # address but different)?
            conflicting_records = session.query(NetworkNode).filter(
                (NetworkNode.iid != node_iid) & (
                        (NetworkNode.p2p_address == f"{p2p_address[0]}:{p2p_address[1]}") |
                        ((
                                 NetworkNode.rest_address == f"{rest_address[0]}:{rest_address[1]}") if rest_address else False)
                )
            ).all()

            for record in conflicting_records:
                if record.last_seen > last_seen:
                    logger.debug(f"ignoring network node update -> record with conflicting address but more recent "
                                 f"timestamp found: "
                                 f"\nrecord.iid={record.iid} <> {node_iid}"
                                 f"\nrecord.last_seen={record.last_seen} > {last_seen}"
                                 f"\nrecord.p2p_address={record.p2p_address} <> {p2p_address}"
                                 f"\nrecord.rest_address={record.rest_address} <> {rest_address}")
                    return

            # the pending update is more recent than any of the conflicting records -> delete the outdated conflicts
            for record in conflicting_records:
                session.query(NetworkNode).filter_by(iid=record.iid).delete()
                session.commit()

            # do we already have a record for this node? only update if either the record does not exist yet OR if
            # the information provided is more recent.
            record = session.query(NetworkNode).filter_by(iid=node_iid).first()
            if record is None:
                session.add(NetworkNode(iid=node_iid, last_seen=last_seen,
                                        dor_service=dor_service, rti_service=rti_service,
                                        p2p_address=f"{p2p_address[0]}:{p2p_address[1]}",
                                        rest_address=f"{rest_address[0]}:{rest_address[1]}" if rest_address else None))
                session.commit()

            elif last_seen > record.last_seen:
                record.last_seen = last_seen
                record.dor_service = dor_service
                record.rti_service = rti_service
                record.p2p_address = f"{p2p_address[0]}:{p2p_address[1]}"
                record.rest_address = f"{rest_address[0]}:{rest_address[1]}" if rest_address else None
                session.commit()

            else:
                logger.debug(f"ignoring network node update -> more recent record found: "
                             f"\nrecord.iid={record.iid} <> {node_iid}"
                             f"\nrecord.last_seen={record.last_seen} > {last_seen}"
                             f"\nrecord.p2p_address={record.p2p_address} <> {p2p_address}"
                             f"\nrecord.rest_address={record.rest_address} <> {rest_address}")
                return

    def remove_network(self, node_iid: str) -> None:
        with self._Session() as session:
            record = session.query(NetworkNode).get(node_iid)
            if record is not None:
                session.query(NetworkNode).filter_by(iid=node_iid).delete()
                session.commit()

    def resolve_network(self, p2p_address: (str, int)) -> Optional[str]:
        with self._Session() as session:
            record = session.query(NetworkNode).filter_by(p2p_address=f"{p2p_address[0]}:{p2p_address[1]}").first()
            return record.iid if record else None

    def get_network(self, node_iid: str) -> Optional[dict]:
        with self._Session() as session:
            record = session.query(NetworkNode).get(node_iid)
            return {
                'iid': record.iid,
                'last_seen': record.iid,
                'p2p_address': record.p2p_address.split(':'),
                'rest_address': record.rest_address.split(':') if record.rest_address else None,
                'dor_service': record.dor_service,
                'rti_service': record.rti_service
            } if record else None

    def get_network_all(self) -> list[NetworkNode]:
        with self._Session() as session:
            return session.query(NetworkNode).all()

    def add_recipe(self, c_hash: str, recipe: dict) -> None:
        with self._Session() as session:
            # convert recipe into string
            recipe = canonicaljson.encode_canonical_json(recipe)
            recipe = recipe.decode('utf-8')

            # calculate recipe hash
            r_hash = hash_string_object(recipe).hex()

            # do we already have this recipe for the given content hash?
            if r_hash in self.get_recipe(c_hash):
                logger.info(f"recipe {r_hash} for content {c_hash} already exists -> not adding")
                return

            # add the provenance record
            record = DataObjectRecipe(c_hash=c_hash, r_hash=r_hash, recipe=recipe)
            session.add(record)
            session.commit()

    def get_recipe(self, c_hash: str) -> dict[str, dict]:
        with self._Session() as session:
            return {record.r_hash: json.loads(record.recipe) for record in
                    session.query(DataObjectRecipe).filter_by(c_hash=c_hash).all()}

    def get_provenance(self, obj_id: str) -> dict:
        # the data object of interest to serve as starting point for the provenance lookup
        self._require_data_object(obj_id)
        obj = self.get_object_by_id(obj_id)
        c_hash0 = obj['c_hash']

        # create lists of nodes (obj and procs) and edges
        content_nodes = []
        proc_nodes = []
        steps = []

        cache = {}
        gpp_cache = {}

        # first: collect all recipes in the history of this data object
        all_recipes = {}
        pending: list[dict] = [*self.get_recipe(c_hash0).values()]
        while len(pending) > 0:
            recipe = pending.pop(0)

            # TODO: what is the correct behaviour? if multiple recipes produce a data object with c_hash then
            #  whichever recipe processed last in the loop would the one that remains set in the all_recipes
            #  dict. that's not wrong. because all we need is ONE recipe that can created the data object.
            #  however, it's not entirely right either. because the same content (i.e., same c_hash) can be
            #  produced by different processors that would produce a data object with different data types and
            #  formats. that would mean that the resulting data object (despite having the same c_hash) to be
            #  incompatible as input for a processor as part of this provenance history. one solution could
            #  be to filter recipes by ones that produce the correct data type/format.
            all_recipes[recipe['product']['c_hash']] = recipe
            # print(json.dumps(recipe, indent=2))

            # handle the processor
            gpp_hash = hash_json_object(recipe['processor']['gpp']).hex()
            gpp_cache[recipe['product']['c_hash']] = gpp_hash
            if gpp_hash not in cache:
                node = {
                    'gpp_hash': gpp_hash,
                    'gpp': recipe['processor']['gpp']
                }
                cache[gpp_hash] = node
                proc_nodes.append(node)
                # print(json.dumps(node, indent=2))

            # handle inputs and add more recipes (if any)
            for obj in recipe['input']:
                pending += [*self.get_recipe(obj['c_hash']).values()]

        # second: collect all data object nodes that are 'derived'
        for recipe in all_recipes.values():
            node = {
                'c_hash': recipe['product']['c_hash'],
                'type': 'derived',
                'data_type': recipe['product']['data_type'],
                'data_format': recipe['product']['data_format']
            }
            cache[node['c_hash']] = node
            content_nodes.append(node)
            # print(json.dumps(node, indent=2))

        # third: collect all the data object nodes that are 'original'
        for recipe in all_recipes.values():
            for obj in recipe['input']:
                if obj['c_hash'] not in cache:
                    node = {
                        'c_hash': obj['c_hash'],
                        'type': 'original',
                        'data_type': obj['data_type'],
                        'data_format': obj['data_format']
                    }
                    cache[node['c_hash']] = node
                    content_nodes.append(node)
                    # print(json.dumps(node, indent=2))

        # fourth: determine all the individual steps
        for recipe in all_recipes.values():
            c_hash = recipe['product']['c_hash']
            consume = [o['c_hash'] for o in all_recipes[c_hash]['input']]
            step = {
                'consume': consume,
                'processor': gpp_cache[c_hash],
                'produce': c_hash
            }
            steps.append(step)

        return {
            'content_nodes': content_nodes,
            'proc_nodes': proc_nodes,
            'steps': steps,
        }

    # END: things that DO require synchronisation

    def create_sync_snapshot(self, exclude_self: bool = False) -> dict:
        identity_items = []
        network_items = []
        recipe_items = []
        with self._Session() as session:
            # add identity records
            for item in session.query(IdentityRecord).all():
                if exclude_self and item.iid == self._node.identity().id:
                    continue

                identity_items.append({
                    'identity': {
                        'iid': item.iid,
                        'name': item.name,
                        'email': item.email,
                        'nonce': item.nonce,
                        's_public_key': item.s_public_key,
                        'e_public_key': item.e_public_key,
                        'signature': item.signature
                    }
                })

            # add network records
            for item in session.query(NetworkNode).all():
                if exclude_self and item.iid == self._node.identity().id:
                    continue

                p2p_address = item.p2p_address.split(':')
                rest_address = item.rest_address.split(':') if item.rest_address else None
                network_items.append({
                    'node_iid': item.iid,
                    'last_seen': item.last_seen,
                    'dor_service': item.dor_service,
                    'rti_service': item.rti_service,
                    'p2p_address': [p2p_address[0], int(p2p_address[1])],
                    'rest_address': [rest_address[0], int(rest_address[1])] if rest_address else None
                })

            # add recipe records
            for item in session.query(DataObjectRecipe).all():
                recipe_items.append({
                    'c_hash': item.c_hash,
                    'recipe': json.loads(item.recipe)
                })

        return {
            'update_identity': identity_items,
            'update_network': network_items,
            'add_recipe': recipe_items
        }
