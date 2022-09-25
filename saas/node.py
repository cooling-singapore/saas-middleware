from __future__ import annotations

import os
from threading import Lock
from typing import Optional

from saascore.api.sdk.proxies import dor_endpoint_prefix, db_endpoint_prefix, rti_endpoint_prefix
from saascore.helpers import get_timestamp_now
from saascore.keystore.identity import Identity
from saascore.keystore.keystore import Keystore
from saascore.log import Logging

import saas.p2p.service as p2p_service
import saas.dor.service as dor_service
import saas.rest.service as rest_service
import saas.rti.service as rti_service
import saas.nodedb.service as db_service
from saas.nodedb.schemas import NodeInfo

logger = Logging.get('node')


class Node:
    def __init__(self, keystore: Keystore, datastore_path: str) -> None:
        # create datastore (if it doesn't already exist)
        os.makedirs(datastore_path, exist_ok=True)

        self._mutex = Lock()
        self._datastore_path = datastore_path
        self._keystore = keystore
        self.db: Optional[db_service.NodeDBService] = None
        self.p2p: Optional[p2p_service.P2PService] = None
        self.rest: Optional[rest_service.RESTService] = None
        self.dor: Optional[dor_service.DORService] = None
        self.rti: Optional[rti_service.RTIService] = None

    @property
    def keystore(self) -> Keystore:
        return self._keystore

    @property
    def identity(self) -> Identity:
        return self._keystore.identity

    @property
    def datastore(self) -> str:
        return self._datastore_path

    def startup(self, server_address: (str, int), enable_dor: bool, enable_rti: bool, enable_db: bool = True,
                rest_address: (str, int) = None, boot_node_address: (str, int) = None,
                retain_job_history: bool = False) -> None:
        logger.info("starting P2P service.")
        self.p2p = p2p_service.P2PService(self, server_address)
        self.p2p.start_service()

        endpoints = []
        if enable_db:
            db_path = f"sqlite:///{os.path.join(self._datastore_path, 'node.db')}"
            logger.info(f"enabling NodeDB service using {db_path}.")
            self.db = db_service.NodeDBService(self, db_endpoint_prefix, db_path)
            self.p2p.add(self.db.protocol)
            endpoints += self.db.endpoints()

        if enable_dor:
            db_path = f"sqlite:///{os.path.join(self._datastore_path, 'dor.db')}"
            logger.info(f"enabling DOR service using {db_path}.")
            self.dor = dor_service.DORService(self, dor_endpoint_prefix, db_path)
            self.p2p.add(self.dor.protocol)
            endpoints += self.dor.endpoints()

        if enable_rti:
            self.rti = rti_service.RTIService(self, rti_endpoint_prefix, retain_job_history)
            logger.info("enabling RTI service.")
            endpoints += self.rti.endpoints()

        if rest_address is not None:
            logger.info("starting REST service.")
            self.rest = rest_service.RESTService(self, rest_address[0], rest_address[1])
            self.rest.start_service()
            self.rest.add(endpoints)

        # update our node db
        self.db.update_identity(self.identity)
        self.db.update_network(NodeInfo(
            identity=self.identity,
            last_seen=get_timestamp_now(),
            dor_service=self.dor is not None,
            rti_service=self.rti is not None,
            p2p_address=self.p2p.address(),
            rest_address=self.rest.address() if self.rest else None
        ))

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
        self.db.protocol.perform_leave()

    def update_identity(self, name: str = None, email: str = None, propagate: bool = True) -> Identity:
        with self._mutex:
            # perform update on the keystore
            identity = self._keystore.update_profile(name=name, email=email)

            # user the identity and update the node db
            self.db.update_identity(identity)

            # propagate only if flag is set
            if propagate:
                self.db.protocol.broadcast_identity_update(identity)

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
