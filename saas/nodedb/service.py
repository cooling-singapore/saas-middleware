import logging

from operator import and_

from sqlalchemy import Column, String, BigInteger, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from saas.cryptography.eckeypair import ECKeyPair
from saas.keystore.keystore import verify_identity_record

logger = logging.getLogger('nodedb.service')

Base = declarative_base()


class DORObject(Base):
    __tablename__ = 'dor_object'
    obj_id = Column(String(64), primary_key=True)
    d_hash = Column(String(64), nullable=False)
    c_hash = Column(String(64), nullable=False)
    owner_iid = Column(String(64), nullable=False)
    expiration = Column(BigInteger)


class DORTag(Base):
    __tablename__ = 'dor_tag'
    obj_id = Column(String(64), primary_key=True)
    key = Column(String(64), primary_key=True)
    value = Column(String(256))


class DORPermission(Base):
    __tablename__ = 'dor_permission'
    obj_id = Column(String(64), primary_key=True)
    key_iid = Column(String(64), primary_key=True)
    permission = Column(String, nullable=False)


class Identity(Base):
    __tablename__ = 'identity'
    iid = Column(String(64), primary_key=True)
    public_key = Column(String, nullable=False)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    nonce = Column(Integer, nullable=False)
    signature = Column(String, nullable=True)


class NodeDBService:
    def __init__(self, db_path, protocol):
        self._protocol = protocol
        self._engine = create_engine(db_path)
        Base.metadata.create_all(self._engine)
        self._Session = sessionmaker(bind=self._engine)

    def update_tags(self, obj_id, tags, propagate=True):
        with self._Session() as session:
            for tag in tags:
                item = session.query(DORTag).filter_by(obj_id=obj_id, key=tag['key']).first()
                if item:
                    item.value = tag['value']
                else:
                    session.add(DORTag(obj_id=obj_id, key=tag['key'], value=tag['value']))
            session.commit()

            if propagate:
                self._protocol.broadcast('update_tags', {
                    'obj_id': obj_id,
                    'tags': tags,
                    'propagate': False
                })

    def remove_tags(self, obj_id, keys=None, propagate=True):
        with self._Session() as session:
            if keys:
                for key in keys:
                    session.query(DORTag).filter_by(obj_id=obj_id, key=key).delete()
            else:
                session.query(DORTag).filter_by(obj_id=obj_id).delete()

            session.commit()

            if propagate:
                self._protocol.broadcast('remove_tags', {
                    'obj_id': obj_id,
                    'keys': keys,
                    'propagate': False
                })

    def get_tags(self, obj_id):
        with self._Session() as session:
            tags = session.query(DORTag).filter_by(obj_id=obj_id).all()

            result = {}
            for tag in tags:
                result[tag.key] = tag.value
            return result

    def find_data_objects(self, key_criterion=None, value_criterion=None):
        # if no criterion is specified, then simply return an empty list.
        # another option could be to return *all* data object ids but that's a potential issue with size and
        # confidentiality
        result = []
        if key_criterion or value_criterion:
            with self._Session() as session:
                if key_criterion and value_criterion:
                    arg = and_(DORTag.key.like(key_criterion), DORTag.value.like(value_criterion))
                elif key_criterion:
                    arg = DORTag.key.like(key_criterion)
                else:
                    arg = DORTag.value.like(value_criterion)

                tags = session.query(DORTag).filter(arg).all()
                for tag in tags:
                    result.append(tag.obj_id)

        return result

    def get_access_list(self, obj_id):
        with self._Session() as session:
            permissions = session.query(DORPermission).filter_by(obj_id=obj_id).all()

            result = []
            for permission in permissions:
                result.append(permission.key_iid)
            return result

    def has_access(self, obj_id, key):
        with self._Session() as session:
            permission = session.query(DORPermission).filter_by(obj_id=obj_id, key_iid=key.iid).first()
            return permission is not None

    def grant_access(self, obj_id, public_key, permission):
        # resolve the identity of the public key
        identity = self.resolve_identity(public_key)

        with self._Session() as session:
            item = session.query(DORPermission).filter_by(obj_id=obj_id, key_iid=identity.iid).first()
            if item:
                item.permission = permission
            else:
                session.add(DORPermission(obj_id=obj_id, key_iid=identity.iid, permission=permission))

            session.commit()

    def revoke_access(self, obj_id, public_key=None):
        with self._Session() as session:
            if not public_key:
                session.query(DORPermission).filter_by(obj_id=obj_id).delete()
            else:
                # resolve the identity of the public key
                identity = self.resolve_identity(public_key)
                session.query(DORPermission).filter_by(obj_id=obj_id, key_iid=identity.iid).delete()

            session.commit()

    def add_data_object(self, obj_id, d_hash, c_hash, owner_public_key, expiration):
        with self._Session() as session:
            item = session.query(DORObject).get(obj_id)
            if not item:
                # resolve the identity of the owner
                owner = self.resolve_identity(owner_public_key)

                # add a new data object record
                session.add(DORObject(obj_id=obj_id, d_hash=d_hash, c_hash=c_hash, owner_iid=owner.iid,
                                      expiration=expiration))
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

    def get_owner(self, obj_id):
        with self._Session() as session:
            item = session.query(DORObject).filter_by(obj_id=obj_id).first()
            if item:
                return self.get_public_key(item.owner_iid)
            else:
                return None

    def update_ownership(self, obj_id, new_owner_public_key):
        with self._Session() as session:
            item = session.query(DORObject).filter_by(obj_id=obj_id).first()
            if item:
                # resolve the identity of the owner
                new_owner = self.resolve_identity(new_owner_public_key)

                #
                # key = ECKeyPair.from_public_key_string(new_owner_public_key)
                # self.update_public_key(key.iid, key.public_as_string())

                item.owner_iid = new_owner.iid
                session.commit()

    def resolve_identity(self, public_key_as_string):
        # if we don't have the identity already in the table, then we create a record to allow for mapping of
        # idd's to public keys. the record will indicate identity as 'unknown'. if we ever get an identity
        # update, the record will be amended accordingly.
        identity = ECKeyPair.from_public_key_string(public_key_as_string)
        if not self.get_public_key(identity.iid):
            self.update_identity(public_key_as_string, 'unknown', 'unknown', 0, propagate=False)

        return identity

    def update_identity(self, public_key_as_string, name, email, nonce, signature=None, propagate=True):
        # get the key and check the signature (if any)
        public_key = ECKeyPair.from_public_key_string(public_key_as_string)
        has_valid_signature = verify_identity_record(public_key, name, email, nonce, signature) if signature else False

        with self._Session() as session:
            # do we have the identity already on record? only update if either the record does not exist yet OR if
            # the information provided is valid and more recent, i.e., if the nonce is greater than the one on record.
            record = session.query(Identity).filter_by(iid=public_key.iid).first()
            if record is None:
                session.add(Identity(iid=public_key.iid, public_key=public_key.public_as_string(), name=name,
                                     email=email, nonce=nonce, signature=signature))
                session.commit()

            else:
                # is the update valid (i.e., does the signature match)?
                if not has_valid_signature:
                    logger.warning(f"ignoring identity update (no signature or invalid signature): "
                                   f"public_key={public_key.public_as_string()} name={name} email={email} "
                                   f"nonce={nonce} signature={signature}")
                    return

                elif nonce > record.nonce:
                    record.name = name
                    record.email = email
                    record.nonce = nonce
                    record.signature = signature
                    session.commit()

                else:
                    logger.debug(f"ignoring identity update (more recent nonce={record.nonce} on record): "
                                 f"public_key={public_key.public_as_string()} name={name} email={email} nonce={nonce} "
                                 f"signature={signature}")

        # propagate only if flag is set AND there is a valid signature
        if propagate and has_valid_signature:
            self._protocol.broadcast('update_identity', {
                'public_key_as_string': public_key.public_as_string(),
                'name': name,
                'email': email,
                'nonce': nonce,
                'signature': signature,
                'propagate': False
            })

    def get_public_key(self, iid):
        identity = self.get_identity_record(iid)
        return ECKeyPair.from_public_key_string(identity.public_key) if identity else None

    def get_identity_record(self, iid=None):
        with self._Session() as session:
            if iid:
                return session.query(Identity).filter_by(iid=iid).first()

            else:
                return session.query(Identity).all()

    def handle_update(self, update):
        method = getattr(self, update['method'])
        method(**update['args'])

