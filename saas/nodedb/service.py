import json
import logging

from sqlalchemy import Column, String, BigInteger, Integer, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from saas.cryptography.eckeypair import ECKeyPair
from saas.cryptography.rsakeypair import RSAKeyPair
from saas.helpers import generate_random_string
from saas.keystore.identity import Identity

logger = logging.getLogger('nodedb.service')

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


def tags_match_patterns(tag_records, patterns):
    for tag_record in tag_records:
        for pattern in patterns:
            if pattern in tag_record.key or pattern in tag_record.value:
                return True
    return False


class NodeDBService:
    def __init__(self, node, db_path, protocol):
        self._node = node
        self.protocol = protocol
        self._engine = create_engine(db_path)
        Base.metadata.create_all(self._engine)
        self._Session = sessionmaker(bind=self._engine)

    # BEGIN: things that do NOT require synchronisation/propagation: DORObject, DORTag, DORPermission

    def update_tags(self, obj_id, tags):
        with self._Session() as session:
            for tag in tags:
                item = session.query(DORTag).filter_by(obj_id=obj_id, key=tag['key']).first()
                if item:
                    item.value = tag['value']
                else:
                    session.add(DORTag(obj_id=obj_id, key=tag['key'], value=tag['value']))
            session.commit()

    def remove_tags(self, obj_id, keys=None):
        with self._Session() as session:
            if keys:
                for key in keys:
                    session.query(DORTag).filter_by(obj_id=obj_id, key=key).delete()
            else:
                session.query(DORTag).filter_by(obj_id=obj_id).delete()

            session.commit()

    def get_tags(self, obj_id):
        with self._Session() as session:
            tags = session.query(DORTag).filter_by(obj_id=obj_id).all()

            result = {}
            for tag in tags:
                result[tag.key] = tag.value
            return result

    def find_data_objects(self, patterns, owner_iid=None):
        with self._Session() as session:
            # first, get all the potential object records
            if owner_iid is not None:
                object_records = session.query(DORObject).filter_by(owner_iid=owner_iid).all()
            else:
                object_records = session.query(DORObject).all()

            # second, find all data objects and filter by patterns (if any)
            result = {}
            for obj_record in object_records:
                # get the tags for this object
                tag_records = session.query(DORTag).filter_by(obj_id=obj_record.obj_id).all()

                # any patterns to match?
                if patterns is None or tags_match_patterns(tag_records, patterns):
                    tags = []
                    for tag in tag_records:
                        tags.append(f"{tag.key}={tag.value}")
                    result[obj_record.obj_id] = tags

            return result

    def get_access_list(self, obj_id):
        with self._Session() as session:
            result = []
            records = session.query(DORPermission).filter_by(obj_id=obj_id).all()
            for record in records:
                result.append(record.key_iid)
            return result

    def has_access(self, obj_id, identity):
        with self._Session() as session:
            return session.query(DORPermission).filter_by(obj_id=obj_id, key_iid=identity.id).first() is not None

    def grant_access(self, obj_id, identity):
        with self._Session() as session:
            item = session.query(DORPermission).filter_by(obj_id=obj_id, key_iid=identity.id).first()
            if item is None:
                session.add(DORPermission(obj_id=obj_id, key_iid=identity.id))
            session.commit()
            return identity.id

    def revoke_access(self, obj_id, identity=None):
        with self._Session() as session:
            if not identity:
                session.query(DORPermission).filter_by(obj_id=obj_id).delete()
                session.commit()
                return '*'
            else:
                session.query(DORPermission).filter_by(obj_id=obj_id, key_iid=identity.id).delete()
                session.commit()
                return identity.id

    def add_data_object(self, obj_id, d_hash, c_hash, owner_iid,
                        access_restricted, content_encrypted,
                        data_type, data_format):
        with self._Session() as session:
            item = session.query(DORObject).get(obj_id)
            if not item:
                # add a new data object record
                session.add(DORObject(obj_id=obj_id, d_hash=d_hash, c_hash=c_hash, owner_iid=owner_iid,
                                      access_restricted=access_restricted, content_encrypted=content_encrypted,
                                      data_type=data_type, data_format=data_format))
                session.commit()

    def remove_data_object(self, obj_id):
        with self._Session() as session:
            session.query(DORObject).filter_by(obj_id=obj_id).delete()
            session.commit()
  
    def get_object_by_id(self, obj_id):
        with self._Session() as session:
            return session.query(DORObject).filter_by(obj_id=obj_id).first()

    def get_objects_by_content_hash(self, c_hash):
        with self._Session() as session:
            return session.query(DORObject).filter_by(c_hash=c_hash).all()

    def get_content_key(self, obj_id):
        with self._Session() as session:
            record = session.query(DORObject).filter_by(obj_id=obj_id).first()
            return record.content_key if record else None

    def delete_content_key(self, obj_id):
        with self._Session() as session:
            record = session.query(DORObject).filter_by(obj_id=obj_id).first()
            if record.content_key is not None:
                content_key = record.content_key
                record.content_key = None
                session.commit()
                return content_key
            else:
                return None

    def get_owner(self, obj_id):
        with self._Session() as session:
            item = session.query(DORObject).filter_by(obj_id=obj_id).first()
            if item:
                return self.get_identity(iid=item.owner_iid)
            else:
                return None

    def update_ownership(self, obj_id, new_owner, content_key):
        # get the current owner (=previous owner to be)
        prev_owner = self.get_owner(obj_id)

        with self._Session() as session:
            # get the record for the data object
            record = session.query(DORObject).filter_by(obj_id=obj_id).first()
            if record is None:
                return False

            # update ownership
            record.owner_iid = new_owner.id

            # do we need to send a request?
            if content_key is not None:
                # create the request content and encrypt it using the owners key
                req_id = generate_random_string(16)
                request = json.dumps({
                    'type': 'import_content_key',
                    'req_id': req_id,
                    'obj_id': obj_id,
                    'content_key': content_key,
                    'prev_owner_iid': prev_owner.id,
                    'prev_owner_name': prev_owner.name,
                    'prev_owner_email': prev_owner.email,
                    'node_id': self._node.identity().id,
                    'node_address': self._node.rest.address()

                })
                request = new_owner.encrypt(request.encode('utf-8')).decode('utf-8')

            else:
                request = None

            # send an email to the owner
            if not self._node.email.send_ownership_transfer_notification_to_new_owner(new_owner, prev_owner, obj_id,
                                                                                      self._node.rest.address(),
                                                                                      request):
                error = f"sending content key request failed."
                logger.error(error)

                # if it failed, we need to change the ownership record back
                record.owner_iid = prev_owner.id

                session.commit()
                return False

            # send email to the previous owner
            self._node.email.send_ownership_transfer_notification_to_prev_owner(new_owner, prev_owner, obj_id,
                                                                                self._node.rest.address())

            # revoke all access to this data object
            self.revoke_access(obj_id)

            # grant access to the new owner
            self.grant_access(obj_id, new_owner)

            session.commit()
            return True

    # END: things that do NOT require synchronisation/propagation

    # BEGIN: things that DO require synchronisation/propagation: Identity, NetworkNode

    def get_identity(self, iid=None, public_key=None):
        with self._Session() as session:
            if iid is not None:
                record = session.query(IdentityRecord).filter_by(iid=iid).first()
            elif public_key is not None:
                record = session.query(IdentityRecord).filter_by(public_key=public_key).first()
            else:
                record = None

            if record is not None:
                return Identity(record.iid, record.name, record.email,
                                ECKeyPair.from_public_key_string(record.s_public_key) if record.s_public_key else None,
                                RSAKeyPair.from_public_key_string(record.e_public_key) if record.e_public_key else None,
                                record.nonce, record.signature)

            else:
                return None

    def get_all_identities(self):
        result = {}
        with self._Session() as session:
            for record in session.query(IdentityRecord).all():
                result[record.iid] = Identity(record.iid, record.name, record.email,
                                              ECKeyPair.from_public_key_string(record.s_public_key),
                                              RSAKeyPair.from_public_key_string(record.e_public_key),
                                              record.nonce, record.signature)

        return result

    def update_identity(self, identity_as_json, propagate=True):
        identity = Identity.deserialise_from_json(identity_as_json)

        # verify the signature
        if not identity.is_authentic():
            logger.warning(f"ignoring identity update (invalid signature): identity={identity.serialise()}")
            return False

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

            else:
                if identity.nonce > record.nonce:
                    record.name = identity.name
                    record.email = identity.email
                    record.nonce = identity.nonce
                    record.s_key = identity.s_public_key_as_string()
                    record.e_key = identity.e_public_key_as_string()
                    record.signature = identity.signature
                    session.commit()

                else:
                    logger.debug(f"ignoring identity update (more recent nonce={record.nonce} on record): "
                                 f"identity={identity.serialise()}")
                    return False

        # propagate only if flag is set
        if propagate:
            self.protocol.broadcast_update('update_identity', {
                'identity_as_json': identity.serialise(as_json=True),
                'propagate': False
            })

        return True

    def update_network_node(self, node_iid, last_seen, p2p_address, rest_address=None, propagate=True):
        with self._Session() as session:
            # do we already have a record for this node? only update if either the record does not exist yet OR if
            # the information provided is more recent.
            record = session.query(NetworkNode).filter_by(iid=node_iid).first()
            if record is None:
                session.add(NetworkNode(iid=node_iid, last_seen=last_seen, p2p_address=p2p_address,
                                        rest_address=rest_address))
                session.commit()

            elif last_seen > record.last_seen:
                record.last_seen = last_seen
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
                'p2p_address': p2p_address,
                'rest_address': rest_address,
                'propagate': False
            })

    def get_network_node(self, node_iid):
        with self._Session() as session:
            return session.query(NetworkNode).filter_by(iid=node_iid).first()

    def get_network(self):
        with self._Session() as session:
            return session.query(NetworkNode).all()

    def remove_network_node(self, node_iid):
        with self._Session() as session:
            session.query(NetworkNode).filter_by(iid=node_iid).delete()
            session.commit()

    # END: things that DO require synchronisation/propagation

    def create_sync_snapshot(self):
        identity_items = []
        network_node_items = []
        with self._Session() as session:
            for item in session.query(IdentityRecord).all():
                identity_items.append({
                    'identity_as_json': {
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
                    'p2p_address': item.p2p_address,
                    'rest_address': item.rest_address,
                    'propagate': False
                })

        return {
            'update_identity': identity_items,
            'update_network_node': network_node_items
        }
