from __future__ import annotations

import os
from threading import Lock
from typing import Optional

from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.keystore.identity import Identity
from saas.keystore.keystore import Keystore
from saas.logging import Logging
from saas.nodedb.protocol import NodeDBP2PProtocol
from saas.p2p.service import P2PService
from saas.dor.service import DataObjectRepositoryService
from saas.rest.service import RESTService
from saas.rti.service import RuntimeInfrastructureService
from saas.nodedb.service import NodeDBService

import saas.dor.blueprint as dor_blueprint
import saas.rti.blueprint as rti_blueprint
import saas.nodedb.blueprint as nodedb_blueprint
from saas.helpers import get_timestamp_now

logger = Logging.get('node')


class Node:
    def __init__(self, keystore: Keystore, datastore_path: str) -> None:
        # create datastore (if it doesn't already exist)
        os.makedirs(datastore_path, exist_ok=True)

        self._mutex = Lock()
        self._datastore_path = datastore_path
        self._keystore = keystore
        self.db: Optional[NodeDBService] = None
        self.p2p: Optional[P2PService] = None
        self.rest: Optional[RESTService] = None
        self.dor: Optional[DataObjectRepositoryService] = None
        self.rti: Optional[RuntimeInfrastructureService] = None

    @property
    def keystore(self) -> Keystore:
        return self._keystore

    @property
    def identity(self) -> Identity:
        return self._keystore.identity

    @property
    def datastore(self) -> str:
        return self._datastore_path

    def startup(self, server_address: (str, int), enable_dor: bool, enable_rti: bool,
                rest_address: (str, int) = None, boot_node_address: (str, int) = None) -> None:
        logger.info("starting P2P service.")
        self.p2p = P2PService(self, server_address)
        self.p2p.start_service()

        logger.info("starting NodeDB service.")
        protocol = NodeDBP2PProtocol(self)
        self.db = NodeDBService(self, f"sqlite:///{os.path.join(self._datastore_path, 'node.db')}", protocol)
        self.p2p.add(protocol)

        if enable_dor:
            logger.info("starting DOR service.")
            self.dor = DataObjectRepositoryService(self)
            self.p2p.add(DataObjectRepositoryP2PProtocol(self))

        if enable_rti:
            logger.info("starting RTI service.")
            self.rti = RuntimeInfrastructureService(self)

        if rest_address is not None:
            blueprint_dor = dor_blueprint.DORBlueprint(self)
            blueprint_rti = rti_blueprint.RTIBlueprint(self)
            blueprint_nodedb = nodedb_blueprint.NodeDBBlueprint(self)

            logger.info("starting REST service.")
            self.rest = RESTService(self, rest_address)
            self.rest.add(blueprint_dor.generate_blueprint())
            self.rest.add(blueprint_rti.generate_blueprint())
            self.rest.add(blueprint_nodedb.generate_blueprint())
            self.rest.start_service()

        # update our node db
        self.db.update_identity(self.identity)
        self.db.update_network(self.identity.id, get_timestamp_now(),
                               self.dor is not None, self.rti is not None,
                               self.p2p.address(), self.rest.address() if self.rest else None)

        # join an existing network of nodes?
        if boot_node_address:
            self.join_network(boot_node_address)

    def shutdown(self, leave_network: bool = True) -> None:
        if leave_network:
            self.leave_network()
        else:
            logger.warning(f"node shutting down silently (not leaving the network)")

        logger.info("stopping all services.")
        if self.p2p:
            self.p2p.stop_service()

        if self.rest:
            self.rest.stop_service()

    def join_network(self, boot_node_address: (str, int)) -> None:
        self.db.protocol.perform_join(boot_node_address)

    def leave_network(self) -> None:
        self.db.protocol.broadcast_leave()

    def update_identity(self, name: str = None, email: str = None, propagate: bool = True) -> Identity:
        with self._mutex:
            # perform update on the keystore
            identity = self._keystore.update_profile(name=name, email=email)

            # user the identity and update the node db
            self.db.update_identity(identity)

            # propagate only if flag is set
            if propagate:
                self.db.protocol.broadcast_update('update_identity', {
                    'identity': identity.serialise()
                })

            return identity

    @classmethod
    def create(cls, keystore: Keystore, storage_path: str, p2p_address: (str, int),
               boot_node_address: (str, int) = None, rest_address: (str, int) = None,
               enable_dor=False, enable_rti=False) -> Node:

        node = Node(keystore, storage_path)
        node.startup(p2p_address, enable_dor=enable_dor, enable_rti=enable_rti,
                     rest_address=rest_address, boot_node_address=boot_node_address)

        return node
