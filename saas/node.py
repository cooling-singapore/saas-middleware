from __future__ import annotations

import os
from threading import Lock
from typing import Optional

from saascore.helpers import get_timestamp_now
from saascore.keystore.identity import Identity
from saascore.keystore.keystore import Keystore
from saascore.log import Logging

import saas.nodedb.protocol as nodedb_prot
import saas.dor.protocol as dor_prot
import saas.p2p.service as p2p_service
import saas.dor.service as dor_service
import saas.rest.service as rest_service
import saas.rti.service as rti_service
import saas.nodedb.service as nodedb_service
import saas.dor.blueprint as dor_blueprint
import saas.rti.blueprint as rti_blueprint
import saas.nodedb.blueprint as nodedb_blueprint

logger = Logging.get('node')


class Node:
    def __init__(self, keystore: Keystore, datastore_path: str) -> None:
        # create datastore (if it doesn't already exist)
        os.makedirs(datastore_path, exist_ok=True)

        self._mutex = Lock()
        self._datastore_path = datastore_path
        self._keystore = keystore
        self.db: Optional[nodedb_service.NodeDBService] = None
        self.p2p: Optional[p2p_service.P2PService] = None
        self.rest: Optional[rest_service.RESTService] = None
        self.dor: Optional[dor_service.DataObjectRepositoryService] = None
        self.rti: Optional[rti_service.RuntimeInfrastructureService] = None

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
                rest_address: (str, int) = None, boot_node_address: (str, int) = None,
                retain_job_history: bool = False) -> None:
        logger.info("starting P2P service.")
        self.p2p = p2p_service.P2PService(self, server_address)
        self.p2p.start_service()

        logger.info("starting NodeDB service.")
        protocol = nodedb_prot.NodeDBP2PProtocol(self)
        self.db = nodedb_service.NodeDBService(self, f"sqlite:///{os.path.join(self._datastore_path, 'node.db')}", protocol)
        self.p2p.add(protocol)

        if enable_dor:
            logger.info("starting DOR service.")
            self.dor = dor_service.DataObjectRepositoryService(self)
            self.p2p.add(dor_prot.DataObjectRepositoryP2PProtocol(self))

        if enable_rti:
            logger.info("starting RTI service.")
            self.rti = rti_service.RuntimeInfrastructureService(self, retain_job_history)

        if rest_address is not None:
            blueprint_dor = dor_blueprint.DORBlueprint(self)
            blueprint_rti = rti_blueprint.RTIBlueprint(self)
            blueprint_nodedb = nodedb_blueprint.NodeDBBlueprint(self)

            logger.info("starting REST service.")
            self.rest = rest_service.RESTService(self, rest_address)
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
               enable_dor=False, enable_rti=False, retain_job_history=False) -> Node:

        node = Node(keystore, storage_path)
        node.startup(p2p_address, enable_dor=enable_dor, enable_rti=enable_rti,
                     rest_address=rest_address, boot_node_address=boot_node_address,
                     retain_job_history=retain_job_history)

        return node
