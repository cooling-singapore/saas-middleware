from typing import Optional, List

from sqlalchemy import Column, String, BigInteger, Integer, Boolean
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from saas.keystore.identity import Identity
from saas.log import Logging
from saas.nodedb.exceptions import InvalidIdentityError, IdentityNotFoundError
from saas.nodedb.protocol import NodeDBP2PProtocol
from saas.nodedb.proxy import DB_ENDPOINT_PREFIX
from saas.nodedb.schemas import NodeInfo, NodeDBSnapshot
from saas.rest.schemas import EndpointDefinition

logger = Logging.get('nodedb.service')

Base = declarative_base()


class NodeRecord(Base):
    __tablename__ = 'node'
    iid = Column(String(64), primary_key=True)
    last_seen = Column(BigInteger, nullable=False)
    dor_service = Column(Boolean, nullable=False)
    rti_service = Column(Boolean, nullable=False)
    p2p_address = Column(String, nullable=False)
    rest_address = Column(String, nullable=True)


class IdentityRecord(Base):
    __tablename__ = 'identity'
    iid = Column(String(64), primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    s_public_key = Column(String, nullable=True)
    e_public_key = Column(String, nullable=True)
    nonce = Column(Integer, nullable=False)
    signature = Column(String, nullable=True)


class NodeDBService:
    def __init__(self, node, db_path: str):
        # initialise properties
        self._node = node
        self._protocol = NodeDBP2PProtocol(node)

        # initialise database things
        self._engine = create_engine(db_path)
        Base.metadata.create_all(self._engine)
        self._Session = sessionmaker(bind=self._engine)

    @property
    def protocol(self) -> NodeDBP2PProtocol:
        return self._protocol

    def endpoints(self) -> List[EndpointDefinition]:
        return [
            EndpointDefinition('GET', DB_ENDPOINT_PREFIX, 'node',
                               self.get_node, NodeInfo, None),

            EndpointDefinition('GET', DB_ENDPOINT_PREFIX, 'network',
                               self.get_network, List[NodeInfo], None),

            EndpointDefinition('GET', DB_ENDPOINT_PREFIX, 'identity/{iid}',
                               self.get_identity, Optional[Identity], None),

            EndpointDefinition('GET', DB_ENDPOINT_PREFIX, 'identity',
                               self.get_identities, List[Identity], None),

            EndpointDefinition('POST', DB_ENDPOINT_PREFIX, 'identity',
                               self.update_identity, Identity, None),
        ]

    def get_node(self) -> NodeInfo:
        with self._Session() as session:
            record = session.query(NodeRecord).get(self._node.identity.id)
            return NodeInfo(
                identity=self._node.identity,
                last_seen=record.last_seen,
                dor_service=record.dor_service,
                rti_service=record.rti_service,
                p2p_address=record.p2p_address.split(':'),
                rest_address=record.rest_address.split(':') if record.rest_address else None
            )

    def get_network(self) -> List[NodeInfo]:
        with self._Session() as session:
            return [NodeInfo(
                identity=self.get_identity(record.iid, raise_if_unknown=True),
                last_seen=record.last_seen,
                dor_service=record.dor_service,
                rti_service=record.rti_service,
                p2p_address=record.p2p_address.split(':'),
                rest_address=record.rest_address.split(':') if record.rest_address else None
            ) for record in session.query(NodeRecord).all()]

    def update_network(self, node: NodeInfo) -> None:
        with self._Session() as session:
            # find all conflicting records, i.e., records of a node with a different iid but on the same P2P/REST
            # address but different (if any).
            p2p_address = f"{node.p2p_address[0]}:{node.p2p_address[1]}"
            rest_address = f"{node.rest_address[0]}:{node.rest_address[1]}" if node.rest_address else None
            conflicting_records = session.query(NodeRecord).filter(
                (NodeRecord.iid != node.identity.id) & (
                    (NodeRecord.p2p_address == p2p_address) |
                    (NodeRecord.rest_address == rest_address if rest_address else False)
                )
            ).all()

            for record in conflicting_records:
                if record.last_seen >= node.last_seen:
                    logger.debug(f"ignoring network node update -> record with conflicting address but more recent "
                                 f"timestamp found: "
                                 f"\nrecord.iid={record.iid} <> {node.identity.id}"
                                 f"\nrecord.last_seen={record.last_seen} >= {node.last_seen}"
                                 f"\nrecord.p2p_address={record.p2p_address} <> {p2p_address}"
                                 f"\nrecord.rest_address={record.rest_address} <> {rest_address}")
                else:
                    logger.debug(f"deleting record with outdated and conflicting address: "
                                 f"\nrecord.iid={record.iid} <> {node.identity.id}"
                                 f"\nrecord.last_seen={record.last_seen} < {node.last_seen}"
                                 f"\nrecord.p2p_address={record.p2p_address} <> {p2p_address}"
                                 f"\nrecord.rest_address={record.rest_address} <> {rest_address}")

                    session.query(NodeRecord).filter_by(iid=record.iid).delete()
                    session.commit()

            # do we already have a record for this node? only update if either the record does not exist yet OR if
            # the information provided is more recent.
            record = session.query(NodeRecord).filter_by(iid=node.identity.id).first()
            if record is None:
                session.add(NodeRecord(iid=node.identity.id, last_seen=node.last_seen,
                                       dor_service=node.dor_service, rti_service=node.rti_service,
                                       p2p_address=p2p_address, rest_address=rest_address))
                session.commit()

            elif node.last_seen > record.last_seen:
                record.last_seen = node.last_seen
                record.dor_service = node.dor_service
                record.rti_service = node.rti_service
                record.p2p_address = p2p_address
                record.rest_address = rest_address
                session.commit()

            else:
                logger.debug(f"ignoring network node update -> more recent record found: "
                             f"\nrecord.iid={record.iid} <> {node.identity.id}"
                             f"\nrecord.last_seen={record.last_seen} >= {node.last_seen}"
                             f"\nrecord.p2p_address={record.p2p_address} <> {p2p_address}"
                             f"\nrecord.rest_address={record.rest_address} <> {rest_address}")

    def remove_node_by_id(self, identity: Identity) -> None:
        with self._Session() as session:
            session.query(NodeRecord).filter_by(iid=identity.id).delete()
            session.commit()

    def remove_node_by_address(self, address: (str, int)) -> None:
        with self._Session() as session:
            session.query(NodeRecord).filter_by(p2p_address=f"{address[0]}:{address[1]}").delete()
            session.commit()

    def reset_network(self) -> None:
        with self._Session() as session:
            session.query(NodeRecord).filter(NodeRecord.iid != self._node.identity.id).delete()
            session.commit()

    def get_identity(self, iid: str, raise_if_unknown: bool = False) -> Optional[Identity]:
        with self._Session() as session:
            record = session.query(IdentityRecord).filter_by(iid=iid).first()

            if raise_if_unknown and record is None:
                raise IdentityNotFoundError(iid)

            return Identity(
                id=record.iid,
                name=record.name,
                email=record.email,
                s_public_key=record.s_public_key,
                e_public_key=record.e_public_key,
                nonce=record.nonce,
                signature=record.signature
            ) if record else None

    def get_identities(self) -> List[Identity]:
        with self._Session() as session:
            records = session.query(IdentityRecord).all()
            return [
                Identity(
                    id=record.iid,
                    name=record.name,
                    email=record.email,
                    s_public_key=record.s_public_key,
                    e_public_key=record.e_public_key,
                    nonce=record.nonce,
                    signature=record.signature
                ) for record in records
            ]

    def update_identity(self, identity: Identity) -> Identity:
        # verify the integrity of the identity
        if not identity.verify_integrity():
            raise InvalidIdentityError({
                'identity': identity
            })

        # update the db
        with self._Session() as session:
            # do we have the identity already on record?
            record = session.query(IdentityRecord).filter_by(iid=identity.id).first()
            if record is None:
                session.add(IdentityRecord(iid=identity.id, name=identity.name, email=identity.email,
                                           s_public_key=identity.s_public_key, e_public_key=identity.e_public_key,
                                           nonce=identity.nonce, signature=identity.signature))
                session.commit()

            # only perform update if either the record does not exist yet OR if the information provided is valid
            # and more recent, i.e., if the nonce is greater than the one on record.
            elif identity.nonce > record.nonce:
                record.name = identity.name
                record.email = identity.email
                record.nonce = identity.nonce
                record.s_key = identity.s_public_key
                record.e_key = identity.e_public_key
                record.signature = identity.signature
                session.commit()

            else:
                logger.debug("Ignore identity update as nonce on record is more recent.")

        return self.get_identity(identity.id, raise_if_unknown=True)

    def get_snapshot(self, exclude: List[str] = None) -> NodeDBSnapshot:
        # get all nodes we know of (minus the ones to exclude)
        nodes = []
        for node in self.get_network():
            if not exclude or node.identity.id not in exclude:
                nodes.append(node)

        # get all identities we know of (minus the ones to exclude)
        identities = []
        for identity in self.get_identities():
            if not exclude or identity.id not in exclude:
                identities.append(identity)

        return NodeDBSnapshot(update_identity=identities, update_network=nodes)
