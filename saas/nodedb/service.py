from typing import Optional

from sqlalchemy import Column, String, BigInteger, Integer, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.keystore.identity import Identity
from saas.logging import Logging
from saas.nodedb.exceptions import DataObjectNotFoundError, DataObjectAlreadyExistsError, RecordNotFoundError, \
    InvalidIdentityError

logger = Logging.get('nodedb.service')

Base = declarative_base()


class DORObject(Base):
    __tablename__ = 'dor_object'
    obj_id = Column(String(64), primary_key=True)
    d_hash = Column(String(64), nullable=False)
    c_hash = Column(String(64), nullable=False)
    owner_iid = Column(String(64), nullable=False)
    access_restricted = Column(Boolean, nullable=False)
    content_encrypted = Column(Boolean, nullable=False)
    data_type = Column(String(64), nullable=False)
    data_format = Column(String(64), nullable=False)


class DORTag(Base):
    __tablename__ = 'dor_tag'
    obj_id = Column(String(64), primary_key=True)
    key = Column(String(64), primary_key=True)
    value = Column(String(256))


class DORPermission(Base):
    __tablename__ = 'dor_permission'
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

    # BEGIN: things that do NOT require synchronisation/propagation: DORObject, DORTag, DORPermission

    def update_tags(self, obj_id: str, tags: list[dict[str, str]]) -> None:
        with self._Session() as session:
            # does the data object exist?
            obj_record = session.query(DORObject).get(obj_id)
            if obj_record is None:
                raise DataObjectNotFoundError({
                    'obj_id': obj_id
                })

            # update the tags
            for tag in tags:
                item = session.query(DORTag).filter_by(obj_id=obj_id, key=tag['key']).first()
                if item:
                    item.value = tag['value']
                else:
                    session.add(DORTag(obj_id=obj_id, key=tag['key'], value=tag['value']))
            session.commit()

    def remove_tags(self, obj_id: str, keys: list[str] = None) -> None:
        with self._Session() as session:
            # does the data object exist?
            obj_record = session.query(DORObject).get(obj_id)
            if obj_record is None:
                raise DataObjectNotFoundError({
                    'obj_id': obj_id
                })

            # remove specific tags
            if keys:
                for key in keys:
                    session.query(DORTag).filter_by(obj_id=obj_id, key=key).delete()

            # remove all tags
            else:
                session.query(DORTag).filter_by(obj_id=obj_id).delete()

            session.commit()

    def get_tags(self, obj_id: str) -> dict[str, str]:
        with self._Session() as session:
            # does the data object exist?
            obj_record = session.query(DORObject).get(obj_id)
            if obj_record is None:
                raise DataObjectNotFoundError({
                    'obj_id': obj_id
                })

            # get all tags
            tags = session.query(DORTag).filter_by(obj_id=obj_id).all()
            return {tag.key: tag.value for tag in tags}

    def find_data_objects(self, patterns: list[str], owner_iid: str = None) -> dict[str, list]:
        with self._Session() as session:
            # first, get records of all potential data objects
            if owner_iid is not None:
                object_records = session.query(DORObject).filter_by(owner_iid=owner_iid).all()
            else:
                object_records = session.query(DORObject).all()

            # second, filter data objects by patterns (if any)
            result = {}
            for obj_record in object_records:
                # prepare a tags array for the result dict
                tag_records = session.query(DORTag).filter_by(obj_id=obj_record.obj_id).all()
                tags = [{'key': tag.key, 'value': tag.value} for tag in tag_records]

                # check if any of the patterns can be found in the tags. for this purpose, flatten all tags (keys
                # values) into a single string and check if any of the patterns is a substring the flattened string.
                # if we don't have patterns then always add the object.
                flattened = ' '.join(f"{tag['key']} {tag['value']}" for tag in tags)
                if patterns is None or any(pattern in flattened for pattern in patterns):
                    result[obj_record.obj_id] = tags

            return result

    def get_access_list(self, obj_id: str) -> list[str]:
        with self._Session() as session:
            # does the data object exist?
            obj_record = session.query(DORObject).get(obj_id)
            if obj_record is None:
                raise DataObjectNotFoundError({
                    'obj_id': obj_id
                })

            # get list of ids of identities that have access
            records = session.query(DORPermission).filter_by(obj_id=obj_id).all()
            return [record.key_iid for record in records]

    def has_access(self, obj_id: str, identity: Identity) -> bool:
        with self._Session() as session:
            # does the data object exist?
            obj_record = session.query(DORObject).get(obj_id)
            if obj_record is None:
                raise DataObjectNotFoundError({
                    'obj_id': obj_id
                })

            return session.query(DORPermission).filter_by(obj_id=obj_id, key_iid=identity.id).first() is not None

    def grant_access(self, obj_id: str, identity: Identity) -> None:
        with self._Session() as session:
            # does the data object exist?
            obj_record = session.query(DORObject).get(obj_id)
            if obj_record is None:
                raise DataObjectNotFoundError({
                    'obj_id': obj_id
                })

            # grant access (if it hasn't already been granted)
            item = session.query(DORPermission).filter_by(obj_id=obj_id, key_iid=identity.id).first()
            if item is None:
                session.add(DORPermission(obj_id=obj_id, key_iid=identity.id))
                session.commit()

    def revoke_access(self, obj_id: str, identity: Identity = None) -> list[str]:
        with self._Session() as session:
            # does the data object exist?
            obj_record = session.query(DORObject).get(obj_id)
            if obj_record is None:
                raise DataObjectNotFoundError({
                    'obj_id': obj_id
                })

            # query for all or a specific identity
            q = session.query(DORPermission).filter_by(obj_id=obj_id, key_iid=identity.id) if identity else \
                session.query(DORPermission).filter_by(obj_id=obj_id)

            # determine the ids of identities that have their access revoked
            result = [record.key_iid for record in q.all()]

            # revoke access
            q.delete()
            session.commit()

            return result

    def add_data_object(self, obj_id: str, d_hash: str, c_hash: str, owner_iid: str,
                        access_restricted: bool, content_encrypted: bool,
                        data_type: str, data_format: str) -> None:
        with self._Session() as session:
            # does the data object exist?
            obj_record = session.query(DORObject).get(obj_id)
            if obj_record is not None:
                raise DataObjectAlreadyExistsError({
                    'obj_id': obj_id
                })

            # add a new data object record
            session.add(DORObject(obj_id=obj_id, d_hash=d_hash, c_hash=c_hash, owner_iid=owner_iid,
                                  access_restricted=access_restricted, content_encrypted=content_encrypted,
                                  data_type=data_type, data_format=data_format))
            session.commit()

    def remove_data_object(self, obj_id: str) -> None:
        with self._Session() as session:
            # does the data object exist?
            obj_record = session.query(DORObject).get(obj_id)
            if obj_record is None:
                raise DataObjectNotFoundError({
                    'obj_id': obj_id
                })

            # delete the data object
            session.query(DORObject).filter_by(obj_id=obj_id).delete()
            session.commit()

    def get_object_by_id(self, obj_id: str) -> Optional[dict]:
        with self._Session() as session:
            record = session.query(DORObject).get(obj_id)
            return {
                'obj_id': record.obj_id,
                'd_hash': record.d_hash,
                'c_hash': record.c_hash,
                'owner_iid': record.owner_iid,
                'access_restricted': record.access_restricted,
                'content_encrypted': record.content_encrypted,
                'data_type': record.data_type,
                'data_format': record.data_format
            } if record else None

    def get_objects_by_content_hash(self, c_hash: str) -> list[dict]:
        with self._Session() as session:
            records = session.query(DORObject).filter_by(c_hash=c_hash).all()
            return [{
                'obj_id': record.obj_id,
                'd_hash': record.d_hash,
                'c_hash': record.c_hash,
                'owner_iid': record.owner_iid,
                'access_restricted': record.access_restricted,
                'content_encrypted': record.content_encrypted,
                'data_type': record.data_type,
                'data_format': record.data_format
            } for record in records]

    # def get_content_key(self, obj_id: str):
    #     with self._Session() as session:
    #         record = session.query(DORObject).filter_by(obj_id=obj_id).first()
    #         return record.content_key if record else None
    #
    # def delete_content_key(self, obj_id):
    #     with self._Session() as session:
    #         record = session.query(DORObject).filter_by(obj_id=obj_id).first()
    #         if record.content_key is not None:
    #             content_key = record.content_key
    #             record.content_key = None
    #             session.commit()
    #             return content_key
    #         else:
    #             return None

    def get_owner(self, obj_id: str) -> Identity:
        with self._Session() as session:
            # does the data object exist?
            obj_record = session.query(DORObject).get(obj_id)
            if obj_record is None:
                raise DataObjectNotFoundError({
                    'obj_id': obj_id
                })

            return self.get_identity(obj_record.owner_iid)

    def update_ownership(self, obj_id: str, new_owner: Identity, content_key: str = None) -> None:
        with self._Session() as session:
            # does the data object exist?
            obj_record = session.query(DORObject).get(obj_id)
            if obj_record is None:
                raise DataObjectNotFoundError({
                    'obj_id': obj_id
                })

            # transfer of ownership between same identities?
            prev_owner = self.get_identity(obj_record.owner_iid)
            if prev_owner.id == new_owner.id:
                return

            # send notification emails
            self._node.email.send_ownership_transfer_notifications(new_owner, prev_owner, obj_id,
                                                                   self._node.identity(),
                                                                   self._node.p2p.address(),
                                                                   content_key)

            # update ownership
            obj_record.owner_iid = new_owner.id
            session.commit()

        # revoke all access to this data object
        self.revoke_access(obj_id)

        # grant access to the new owner
        self.grant_access(obj_id, new_owner)

    # END: things that do NOT require synchronisation/propagation

    # BEGIN: things that DO require synchronisation/propagation: Identity, NetworkNode

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

    def update_identity(self, serialised_identity: dict, propagate: bool = True) -> None:
        # deserialise the identity and verify its authenticity
        identity = Identity.deserialise(serialised_identity)
        if not identity.is_authentic():
            raise InvalidIdentityError({
                'serialised_identity': serialised_identity
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

        # propagate only if flag is set
        if propagate:
            self.protocol.broadcast_update('update_identity', {
                'serialised_identity': identity.serialise(),
                'propagate': False
            })

    def update_network_node(self, node_iid: str, last_seen: int, dor_service: bool, rti_service: bool,
                            p2p_address: (str, int), rest_address: (str, int) = None, propagate: bool = True) -> None:
        with self._Session() as session:
            # do we already have a record for this node? only update if either the record does not exist yet OR if
            # the information provided is more recent.
            record = session.query(NetworkNode).filter_by(iid=node_iid).first()
            if record is None:
                session.add(NetworkNode(iid=node_iid, last_seen=last_seen,
                                        dor_service=dor_service, rti_service=rti_service,
                                        p2p_address=p2p_address, rest_address=rest_address))
                session.commit()

            elif last_seen > record.last_seen:
                record.last_seen = last_seen
                record.dor_service = dor_service
                record.rti_service = rti_service
                record.p2p_address = p2p_address
                record.rest_address = rest_address
                session.commit()

            else:
                logger.debug(f"ignoring network node update (more recent timestamp={record.last_seen} on record)")

        # propagate only if flag is set
        if propagate:
            self.protocol.broadcast_update('update_network_node', {
                'node_iid': node_iid,
                'last_seen': last_seen,
                'dor_service': dor_service,
                'rti_service': rti_service,
                'p2p_address': p2p_address,
                'rest_address': rest_address,
                'propagate': False
            })

    def get_network_node(self, node_iid: str) -> Optional[dict]:
        with self._Session() as session:
            record = session.query(NetworkNode).get(node_iid)
            return {
                'iid': record.iid,
                'last_seen': record.iid,
                'p2p_address': record.p2p_address.split(':') if record.p2p_address else None,
                'rest_address': record.rest_address.split(':') if record.rest_address else None,
                'dor_service': record.dor_service,
                'rti_service': record.rti_service
            } if record else None

    def get_network(self) -> list[dict]:
        with self._Session() as session:
            records = session.query(NetworkNode).all()
            return [{
                'iid': record.iid,
                'last_seen': record.iid,
                'p2p_address': record.p2p_address.split(':') if record.p2p_address else None,
                'rest_address': record.rest_address.split(':') if record.rest_address else None,
                'dor_service': record.dor_service,
                'rti_service': record.rti_service
            } for record in records]

    def remove_network_node(self, node_iid: str) -> None:
        with self._Session() as session:
            record = session.query(NetworkNode).get(node_iid)
            if record is None:
                raise RecordNotFoundError({
                    'table': NetworkNode.__name__,
                    'node_iid': node_iid
                })

            session.query(NetworkNode).filter_by(iid=node_iid).delete()
            session.commit()

    # END: things that DO require synchronisation/propagation

    def create_sync_snapshot(self) -> dict:
        identity_items = []
        network_node_items = []
        with self._Session() as session:
            for item in session.query(IdentityRecord).all():
                identity_items.append({
                    'serialised_identity': {
                        'iid': item.iid,
                        'name': item.name,
                        'email': item.email,
                        'nonce': item.nonce,
                        's_public_key': item.s_public_key,
                        'e_public_key': item.e_public_key,
                        'signature': item.signature
                    },
                    'propagate': False
                  })

            for item in session.query(NetworkNode).all():
                network_node_items.append({
                    'node_iid': item.iid,
                    'last_seen': item.last_seen,
                    'dor_service': item.dor_service,
                    'rti_service': item.rti_service,
                    'p2p_address': item.p2p_address,
                    'rest_address': item.rest_address,
                    'propagate': False
                })

        return {
            'update_identity': identity_items,
            'update_network_node': network_node_items
        }
