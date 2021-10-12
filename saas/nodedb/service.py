import json
from typing import Optional, Union

import canonicaljson
from sqlalchemy import Column, String, BigInteger, Integer, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.hashing import hash_json_object, hash_string_object
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.helpers import get_timestamp_now
from saas.keystore.identity import Identity
from saas.logging import Logging
from saas.nodedb.exceptions import DataObjectNotFoundError, InvalidIdentityError

logger = Logging.get('nodedb.service')

Base = declarative_base()


class DataObjectRecord(Base):
    __tablename__ = 'obj_record'
    obj_id = Column(String(64), primary_key=True)

    # IMMUTABLE part of meta information:
    c_hash = Column(String(64), nullable=False)
    data_type = Column(String(64), nullable=False)
    data_format = Column(String(64), nullable=False)
    created_by = Column(String(64), nullable=False)
    created_t = Column(Integer, nullable=False)
    gpp = Column(Text, nullable=True)

    # MUTABLE part of meta information:
    owner_iid = Column(String(64), nullable=False)
    access_restricted = Column(Boolean, nullable=False)
    content_encrypted = Column(Boolean, nullable=False)


class DataObjectRecipe(Base):
    __tablename__ = 'obj_recipe'
    c_hash = Column(String(64), primary_key=True)
    r_hash = Column(String(64), primary_key=True)
    recipe = Column(Text, nullable=False)


class DataObjectTag(Base):
    __tablename__ = 'obj_tag'
    obj_id = Column(String(64), primary_key=True)
    key = Column(String(64), primary_key=True)
    value = Column(String(256))


class DataObjectAccess(Base):
    __tablename__ = 'obj_access'
    obj_id = Column(String(64), primary_key=True)
    key_iid = Column(String(64), primary_key=True)


class IdentityRecord(Base):
    __tablename__ = 'identity'
    iid = Column(String(64), primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    nonce = Column(Integer, nullable=False)
    s_public_key = Column(String, nullable=True)
    e_public_key = Column(String, nullable=True)
    signature = Column(String, nullable=True)


class NetworkNode(Base):
    __tablename__ = 'network_node'
    iid = Column(String(64), primary_key=True)
    last_seen = Column(BigInteger, nullable=False)
    p2p_address = Column(String(21), nullable=False)
    rest_address = Column(String(21), nullable=True)
    dor_service = Column(Boolean, nullable=False)
    rti_service = Column(Boolean, nullable=False)


class NodeDBService:
    def __init__(self, node, db_path, protocol):
        self._node = node
        self.protocol = protocol
        self._engine = create_engine(db_path)
        Base.metadata.create_all(self._engine)
        self._Session = sessionmaker(bind=self._engine)

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

    def find_data_objects(self, patterns: list[str], owner_iid: str = None) -> list[dict]:
        with self._Session() as session:
            # first, get records of all potential data objects
            if owner_iid is not None:
                object_records = session.query(DataObjectRecord).filter_by(owner_iid=owner_iid).all()
            else:
                object_records = session.query(DataObjectRecord).all()

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
                    result.append({
                        'obj_id': obj_record.obj_id,
                        'tags': tags
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
                    ((NetworkNode.rest_address == f"{rest_address[0]}:{rest_address[1]}") if rest_address else False)
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

    def get_network_all(self, valid_json: bool = False) -> list[dict]:
        with self._Session() as session:
            records = session.query(NetworkNode).all()
            result = [{
                'iid': record.iid,
                'last_seen': record.last_seen,
                'p2p_address': record.p2p_address.split(':'),
                'rest_address': record.rest_address.split(':') if record.rest_address else None,
                'dor_service': record.dor_service,
                'rti_service': record.rti_service
            } for record in records]

            # make it a valid JSON object?
            if valid_json:
                for record in result:
                    record['p2p_address'] = f"{record['p2p_address'][0]}:{record['p2p_address'][1]}"
                    if record['rest_address'] is None:
                        record.pop('rest_address')
                    else:
                        record['rest_address'] = f"{record['rest_address'][0]}:{record['rest_address'][1]}"

            return result

    def add_recipe(self, c_hash: str, recipe: Union[dict, str]) -> None:
        with self._Session() as session:
            # convert recipe into string (if necessary)
            recipe = canonicaljson.encode_canonical_json(recipe) if isinstance(recipe, dict) else recipe
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
                    'recipe': item.recipe
                })

        return {
            'update_identity': identity_items,
            'update_network': network_items,
            'add_recipe': recipe_items
        }
