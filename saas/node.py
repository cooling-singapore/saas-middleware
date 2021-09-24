import os
import logging
import time
from threading import Lock
from typing import Optional

from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.email.service import EmailService
from saas.keystore.assets.credentials import CredentialsAsset, SSHCredentials
from saas.keystore.identity import Identity
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

logger = logging.getLogger('node')


class Node:
    def __init__(self, keystore, datastore_path):
        # check if path exists
        if not os.path.isdir(datastore_path):
            os.mkdir(datastore_path)

        self._mutex = Lock()
        self._datastore_path = datastore_path
        self._keystore = keystore
        self.db: Optional[NodeDBService] = None
        self.p2p: Optional[P2PService] = None
        self.rest: Optional[RESTService] = None
        self.dor: Optional[DataObjectRepositoryService] = None
        self.rti: Optional[RuntimeInfrastructureService] = None
        self.email: Optional[EmailService] = None

    @property
    def keystore(self):
        return self._keystore

    def identity(self):
        return self._keystore.identity

    def datastore(self):
        return self._datastore_path

    def startup(self, server_address, enable_dor, enable_rti, rest_address=None, boot_node_address=None, ssh_profile=None):
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
            # are we supposed to use an ssh profile?
            if ssh_profile:
                asset: CredentialsAsset = self._keystore.get_asset('ssh-credentials')
                ssh_credentials: SSHCredentials = asset.get(ssh_profile)
                if ssh_credentials is None:
                    raise RuntimeError(f"SSH profile '{ssh_profile}' but no credentials found for "
                                       f"identity '{self._keystore.identity.id}'.")

                logger.info(f"starting RTI service using SSH profile: {ssh_profile}.")
                self.rti = RuntimeInfrastructureService(self, ssh_credentials=ssh_credentials)

            else:
                logger.info("starting RTI service.")
                self.rti = RuntimeInfrastructureService(self)

        if rest_address is not None:
            blueprint_dor = dor_blueprint.DORBlueprint(self)
            blueprint_rti = rti_blueprint.RTIBlueprint(self)
            blueprint_nodedb = nodedb_blueprint.NodeDBBlueprint(self)

            logger.info("starting REST service.")
            self.rest = RESTService(self, rest_address)
            self.rest.add(blueprint_dor.blueprint())
            self.rest.add(blueprint_rti.blueprint())
            self.rest.add(blueprint_nodedb.blueprint())
            self.rest.start_service()

        # update the identity
        # TODO: is this still needed?
        self.update_identity(propagate=False)

        # update the network node
        self.update_network_node(propagate=False)

        # join an existing network of nodes?
        if boot_node_address:
            self.join_network(boot_node_address)

        self.email = EmailService(self._keystore)

    def shutdown(self):
        self.leave_network()

        logger.info("stopping all services.")
        if self.p2p:
            self.p2p.stop_service()

        if self.rest:
            self.rest.stop_service()

    def join_network(self, boot_node_address):
        logger.info(f"joining network via boot node '{boot_node_address}'.")
        self.db.protocol.send_join(boot_node_address)
        return True

    def leave_network(self):
        logger.info(f"leaving network.")
        self.db.protocol.broadcast_leave()
        time.sleep(2)

    def update_identity(self, name: str = None, email: str = None, propagate: bool = True) -> Identity:
        with self._mutex:
            # perform update on the keystore
            identity = self._keystore.update_profile(name=name, email=email)

            # user the identity and update the node db
            self.db.update_identity(identity.serialise(), propagate=propagate)

            return identity

    def update_network_node(self, propagate=True):
        p2p_address = self.p2p.address()
        rest_address = self.rest.address() if self.rest else None

        self.db.update_network_node(self._keystore.identity.id, get_timestamp_now(),
                                    self.dor is not None, self.rti is not None,
                                    f"{p2p_address[0]}:{p2p_address[1]}",
                                    f"{rest_address[0]}:{rest_address[1]}" if rest_address else None,
                                    propagate=propagate)

    @classmethod
    def create(cls, keystore, storage_path, p2p_address, boot_node_address=None, rest_address=None,
               enable_dor=False, enable_rti=False, ssh_profile: str = None):
        node = Node(keystore, storage_path)

        node.startup(p2p_address, enable_dor=enable_dor, enable_rti=enable_rti,
                     rest_address=rest_address, boot_node_address=boot_node_address, ssh_profile=ssh_profile)

        return node
