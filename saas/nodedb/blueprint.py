import logging
from typing import Optional

from requests import Response

from saas.keystore.identity import Identity
from saas.keystore.schemas import identity_schema
from saas.rest.blueprint import SaaSBlueprint
from saas.rest.envelope import create_ok_response
from saas.rest.proxy import EndpointProxy

from saas.rest.request_manager import request_manager

logger = logging.getLogger('nodedb.blueprint')
endpoint_prefix = "/api/v1/nodedb"


class NodeDBBlueprint(SaaSBlueprint):
    def __init__(self, node):
        super().__init__('nodedb', __name__, endpoint_prefix)
        self._node = node

        self.add_rule('node', self.get_node, methods=['GET'])
        self.add_rule('network', self.get_network, methods=['GET'])
        self.add_rule('identity', self.get_identities, methods=['GET'])
        self.add_rule('identity', self.update_identity, methods=['POST'])
        self.add_rule('identity/<iid>', self.get_identity, methods=['GET'])

    def get_node(self) -> (Response, int):
        return create_ok_response({
            "iid": self._node.identity().id,
            "identity": self._node.identity().serialise(),
            "dor_service": self._node.dor is not None,
            "rti_service": self._node.rti is not None,
            "rest_service_address": self._node.rest.address(),
            "p2p_service_address": self._node.p2p.address()
        })

    def get_network(self) -> (Response, int):
        return create_ok_response(
            self._node.db.get_network_all()
        )

    def get_identities(self) -> (Response, int):
        return create_ok_response(
            [identity.serialise() for identity in self._node.db.get_all_identities().values()]
        )

    def get_identity(self, iid: str) -> (Response, int):
        identity = self._node.db.get_identity(iid)
        return create_ok_response(
            identity.serialise() if identity else None
        )

    @request_manager.verify_request_body(identity_schema)
    def update_identity(self) -> (Response, int):
        serialised_identity = request_manager.get_request_variable('body')
        self._node.db.update_identity(serialised_identity)
        return create_ok_response()


class NodeDBProxy(EndpointProxy):
    def __init__(self, remote_address):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address)

    def get_node(self) -> dict:
        return self.get("/node")

    def get_network(self) -> list[dict]:
        return self.get("/network")

    def get_identities(self) -> dict[str, Identity]:
        return {
            item['iid']: Identity.deserialise(item) for item in self.get("/identity")
        }

    def get_identity(self, iid: str) -> Optional[Identity]:
        return Identity.deserialise(self.get(f"/identity/{iid}"))

    def update_identity(self, identity) -> None:
        self.post('/identity', body=identity.serialise())
