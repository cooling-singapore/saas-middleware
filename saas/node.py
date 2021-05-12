import os
import logging

from saas.dor.protocol import DataObjectRepositoryP2PProtocol
from saas.keystore.keystore import Keystore
from saas.nodedb.protocol import NodeDBP2PProtocol
from saas.p2p.service import P2PService
from saas.registry.service import RegistryService
from saas.registry.protocol import RegistryP2PProtocol
from saas.dor.service import DataObjectRepositoryService
from saas.rest.service import RESTService
from saas.rti.service import RuntimeInfrastructureService
from saas.nodedb.nodedb import NodeDB

import saas.registry.blueprint as registry_blueprint
import saas.dor.blueprint as dor_blueprint
import saas.rti.blueprint as rti_blueprint

logger = logging.getLogger('Node')


class Node:
    def __init__(self, keystore, datastore_path):
        # check if path exists
        if not os.path.isdir(datastore_path):
            raise Exception(f"datastore path '{datastore_path}' does not exist.")

        self._keystore = keystore
        self._datastore_path = datastore_path
        self.p2p = None
        self.rest = None
        self.registry = None
        self.db = None
        self.dor = None
        self.rti = None

    def id(self, truncate=False):
        return self._keystore.id(truncate)

    def name(self):
        return self._keystore.name()

    def identity(self):
        return self._keystore.identity

    def datastore(self):
        return self._datastore_path

    def start_p2p_service(self, server_address):
        logger.info("starting P2P service.")
        self.p2p = P2PService(self, server_address)
        self.p2p.start_service()

    def start_rest_service(self, server_address):
        blueprint_registry = registry_blueprint.RegistryBlueprint(self)
        blueprint_dor = dor_blueprint.DORBlueprint(self)
        blueprint_rti = rti_blueprint.RTIBlueprint(self)

        logger.info("starting REST service.")
        self.rest = RESTService(self, server_address)
        self.rest.add(blueprint_registry.blueprint())
        self.rest.add(blueprint_dor.blueprint())
        self.rest.add(blueprint_rti.blueprint())
        self.rest.start_service()

    def start_registry_service(self):
        logger.info("starting Registry service.")
        self.registry = RegistryService(self)
        self.p2p.add(RegistryP2PProtocol(self))

    def start_nodedb_service(self):
        logger.info("starting NodeDB service.")
        protocol = NodeDBP2PProtocol(self)
        self.db = NodeDB(f"sqlite:///{os.path.join(self._datastore_path, 'node.db')}", protocol)
        self.p2p.add(protocol)

    def start_dor_service(self):
        logger.info("starting DOR service.")
        self.dor = DataObjectRepositoryService(self)
        self.p2p.add(DataObjectRepositoryP2PProtocol(self))

    def start_rti_service(self):
        logger.info("starting DOR service.")
        self.rti = RuntimeInfrastructureService(self)

    def stop_services(self):
        logger.info("stopping all services.")
        if self.p2p:
            self.p2p.stop_service()

        if self.rest:
            self.rest.stop_service()

    @classmethod
    def create(cls, keystore, storage_path, p2p_address=None, rest_address=None, enable_dor=False, enable_rti=False):
        node = Node(keystore, storage_path)

        if p2p_address:
            node.start_p2p_service(p2p_address)

        if rest_address:
            node.start_rest_service(rest_address)

        if enable_dor:
            node.start_dor_service()

        if enable_rti:
            node.start_rti_service()

        node.start_nodedb_service()
        node.start_registry_service()

        return node
