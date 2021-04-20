from operator import and_

from sqlalchemy import Column, String, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from saas.nodedb.protocol import NodeDBP2PProtocol
from saas.cryptography.eckeypair import ECKeyPair

Base = declarative_base()


class DORObject(Base):
    __tablename__ = 'dor_object'
    obj_id = Column(String(64), primary_key=True)
    d_hash = Column(String(64), nullable=False)
    c_hash = Column(String(64), nullable=False)
    owner_iid = Column(String(64), nullable=False)
    custodian_iid = Column(String(64), nullable=False)
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


class PublicKey(Base):
    __tablename__ = 'public_key'
    iid = Column(String(64), primary_key=True)
    public_key = Column(String, nullable=False)


class NodeDB:
    def __init__(self, node):
        # create P2P protocol instance
        self.protocol = NodeDBP2PProtocol(node)

        # initialise database and session maker
        engine = create_engine(node.db_path)
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine)

    def update_tags(self, obj_id, tags, propagate=True):
        with self.Session() as session:
            for tag in tags:
                item = session.query(DORTag).filter_by(obj_id=obj_id, key=tag['key']).first()
                if item:
                    item.value = tag['value']
                else:
                    session.add(DORTag(obj_id=obj_id, key=tag['key'], value=tag['value']))
            session.commit()

            if propagate:
                self.protocol.broadcast('update_tags', {
                    'obj_id': obj_id,
                    'tags': tags,
                    'propagate': False
                })

    def remove_tags(self, obj_id, keys=None, propagate=True):
        with self.Session() as session:
            if keys:
                for key in keys:
                    session.query(DORTag).filter_by(obj_id=obj_id, key=key).delete()
            else:
                session.query(DORTag).filter_by(obj_id=obj_id).delete()

            session.commit()

            if propagate:
                self.protocol.broadcast('remove_tags', {
                    'obj_id': obj_id,
                    'keys': keys,
                    'propagate': False
                })

    def get_tags(self, obj_id):
        with self.Session() as session:
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
            with self.Session() as session:
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

    def update_public_key(self, iid, public_key, propagate=True):
        with self.Session() as session:
            item = session.query(PublicKey).get(iid)
            if not item:
                session.add(PublicKey(iid=iid, public_key=public_key))
                session.commit()

                if propagate:
                    self.protocol.broadcast('update_public_key', {
                        'iid': iid,
                        'public_key': public_key,
                        'propagate': False
                    })

    def get_public_key(self, iid):
        with self.Session() as session:
            item = session.query(PublicKey).get(iid)
            if item:
                return ECKeyPair.from_public_key_string(item.public_key)
            else:
                return None

    def get_access_list(self, obj_id):
        with self.Session() as session:
            permissions = session.query(DORPermission).filter_by(obj_id=obj_id).all()

            result = []
            for permission in permissions:
                result.append(permission.key_iid)
            return result

    def has_access(self, obj_id, key):
        with self.Session() as session:
            permission = session.query(DORPermission).filter_by(obj_id=obj_id, key_iid=key.iid).first()
            return permission is not None

    def grant_access(self, obj_id, public_key, permission):
        key = ECKeyPair.from_public_key_string(public_key)
        self.update_public_key(key.iid, key.public_as_string())

        with self.Session() as session:
            item = session.query(DORPermission).filter_by(obj_id=obj_id, key_iid=key.iid).first()
            if item:
                item.permission = permission
            else:
                session.add(DORPermission(obj_id=obj_id, key_iid=key.iid, permission=permission))
            session.commit()

    def revoke_access(self, obj_id, public_key=None):
        with self.Session() as session:
            if public_key:
                key = ECKeyPair.from_public_key_string(public_key)
                session.query(DORPermission).filter_by(obj_id=obj_id, key_iid=key.iid).delete()
            else:
                session.query(DORPermission).filter_by(obj_id=obj_id).delete()
            session.commit()

    def add_data_object(self, obj_id, d_hash, c_hash, owner_public_key, custodian_public_key,
                        expiration, propagate=True):
        with self.Session() as session:
            item = session.query(DORObject).get(obj_id)
            if not item:
                owner = ECKeyPair.from_public_key_string(owner_public_key)
                custodian = ECKeyPair.from_public_key_string(custodian_public_key)

                self.update_public_key(owner.iid, owner.public_as_string(), propagate=False)
                self.update_public_key(custodian.iid, custodian.public_as_string(), propagate=False)

                session.add(DORObject(obj_id=obj_id, d_hash=d_hash, c_hash=c_hash,
                                      owner_iid=owner.iid, custodian_iid=custodian.iid,
                                      expiration=expiration))
                session.commit()

                if propagate:
                    self.protocol.broadcast('add_data_object', {
                        'obj_id': obj_id,
                        'd_hash': d_hash,
                        'c_hash': c_hash,
                        'owner_public_key': owner_public_key,
                        'custodian_public_key': custodian_public_key,
                        'expiration': expiration,
                        'propagate': False
                    })

    def remove_data_object(self, obj_id):
        with self.Session() as session:
            session.query(DORObject).filter_by(obj_id=obj_id).delete()
            session.commit()

    def get_object_by_id(self, obj_id):
        with self.Session() as session:
            return session.query(DORObject).filter_by(obj_id=obj_id).first()

    def get_objects_by_content_hash(self, c_hash):
        with self.Session() as session:
            return session.query(DORObject).filter_by(c_hash=c_hash).all()

    def get_owner(self, obj_id):
        with self.Session() as session:
            item = session.query(DORObject).filter_by(obj_id=obj_id).first()
            if item:
                return self.get_public_key(item.owner_iid)
            else:
                return None

    def update_ownership(self, obj_id, new_owner_public_key):
        with self.Session() as session:
            item = session.query(DORObject).filter_by(obj_id=obj_id).first()
            if item:
                key = ECKeyPair.from_public_key_string(new_owner_public_key)
                self.update_public_key(key.iid, key.public_as_string())

                item.owner_iid = key.iid
                session.commit()

    def handle_update(self, update):
        method = getattr(self, update['method'])
        method(**update['args'])

