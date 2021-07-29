import os
import logging
import time
from threading import Lock

from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.email.service import EmailService
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
            raise Exception(f"datastore path '{datastore_path}' does not exist.")

        self._mutex = Lock()
        self._datastore_path = datastore_path
        self._keystore = keystore
        self.db = None
        self.p2p = None
        self.rest = None
        self.dor = None
        self.rti = None
        self.email = None

    def identity(self):
        return self._keystore.identity()

    def signing_key(self):
        return self._keystore.signing_key()

    def encryption_key(self):
        return self._keystore.encryption_key()

    def datastore(self):
        return self._datastore_path

    def startup(self, server_address, boot_node_address=None):
        logger.info("starting P2P service.")
        self.p2p = P2PService(self, server_address)
        self.p2p.start_service()

        logger.info("starting NodeDB service.")
        protocol = NodeDBP2PProtocol(self)
        self.db = NodeDBService(self, f"sqlite:///{os.path.join(self._datastore_path, 'node.db')}", protocol)
        self.p2p.add(protocol)

        self.update_identity(propagate=False)
        self.update_network_node(propagate=False)

        if boot_node_address:
            self.join_network(boot_node_address)

        if self._keystore.has_smtp_information():
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

    def start_rest_service(self, server_address):
        blueprint_dor = dor_blueprint.DORBlueprint(self)
        blueprint_rti = rti_blueprint.RTIBlueprint(self)
        blueprint_nodedb = nodedb_blueprint.NodeDBBlueprint(self)

        logger.info("starting REST service.")
        self.rest = RESTService(self, server_address)
        self.rest.add(blueprint_dor.blueprint())
        self.rest.add(blueprint_rti.blueprint())
        self.rest.add(blueprint_nodedb.blueprint())
        self.rest.start_service()

        self.update_network_node(propagate=True)

    def start_dor_service(self):
        logger.info("starting DOR service.")
        self.dor = DataObjectRepositoryService(self)
        self.p2p.add(DataObjectRepositoryP2PProtocol(self))

    def start_rti_service(self):
        logger.info("starting DOR service.")
        self.rti = RuntimeInfrastructureService(self)

    def update_identity(self, s_key=None, e_key=None, name=None, email=None, propagate=True):
        with self._mutex:
            # perform update on the keystore
            signature = self._keystore.update(s_key=s_key, e_key=e_key, name=name, email=email)

            # user the identity and update the node db
            identity = self._keystore.identity()
            self.db.update_identity(identity.serialise(), signature, propagate=propagate)

            return identity, signature

    def update_network_node(self, propagate=True):
        p2p_address = self.p2p.address()
        rest_address = self.rest.address() if self.rest else None

        self.db.update_network_node(self._keystore.identity().id(), get_timestamp_now(),
                                    f"{p2p_address[0]}:{p2p_address[1]}",
                                    f"{rest_address[0]}:{rest_address[1]}" if rest_address else None,
                                    propagate=propagate)

    @classmethod
    def create(cls, keystore, storage_path, p2p_address, boot_node_address=None, rest_address=None,
               enable_dor=False, enable_rti=False):
        node = Node(keystore, storage_path)

        node.startup(p2p_address, boot_node_address)

        if rest_address:
            node.start_rest_service(rest_address)

        if enable_dor:
            node.start_dor_service()

        if enable_rti:
            node.start_rti_service()

        return node
