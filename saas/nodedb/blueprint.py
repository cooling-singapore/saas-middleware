from typing import Optional

from requests import Response

from saas.keystore.identity import Identity
from saas.keystore.schemas import identity_schema
from saas.logging import Logging
from saas.rest.blueprint import SaaSBlueprint, create_ok_response
from saas.rest.proxy import EndpointProxy

from saas.rest.request_manager import request_manager
from saas.schemas import network_node_schema, provenance_schema

logger = Logging.get('nodedb.blueprint')
endpoint_prefix = "/api/v1/nodedb"


network_node_details_schema = {
    'type': 'object',
    'properties': {
        'iid': {'type': 'string'},
        'identity': identity_schema,
        'dor_service': {'type': 'boolean'},
        'rti_service': {'type': 'boolean'},
        'rest_service_address': {'type': 'string'},
        'p2p_service_address': {'type': 'string'}
    },
    'required': ['iid', 'identity', 'dor_service', 'rti_service', 'rest_service_address', 'p2p_service_address']
}

network_nodes_schema = {
    'type': 'array',
    'items': network_node_schema
}

identities_schema = {
    'type': 'array',
    'items': identity_schema
}


class NodeDBBlueprint(SaaSBlueprint):
    def __init__(self, node):
        super().__init__('nodedb', __name__, endpoint_prefix)
        self._node = node

        self.add_rule('node', self.get_node, methods=['GET'])
        self.add_rule('network', self.get_network, methods=['GET'])
        self.add_rule('identity', self.get_identities, methods=['GET'])
        self.add_rule('identity/<iid>', self.get_identity, methods=['GET'])
        self.add_rule('identity', self.update_identity, methods=['POST'])
        self.add_rule('provenance/<obj_id>', self.get_provenance, methods=['GET'])

    @request_manager.handle_request(network_node_details_schema)
    def get_node(self) -> (Response, int):
        p2p_address = self._node.p2p.address()
        rest_address = self._node.rest.address()

        return create_ok_response({
            "iid": self._node.identity().id,
            "identity": self._node.identity().serialise(),
            "dor_service": self._node.dor is not None,
            "rti_service": self._node.rti is not None,
            "rest_service_address": f"{p2p_address[0]}:{p2p_address[1]}",
            "p2p_service_address": f"{rest_address[0]}:{rest_address[1]}" if rest_address else None
        })

    @request_manager.handle_request(network_nodes_schema)
    def get_network(self) -> (Response, int):
        return create_ok_response(
            self._node.db.get_network_all(valid_json=True)
        )

    @request_manager.handle_request(identities_schema)
    def get_identities(self) -> (Response, int):
        return create_ok_response(
            [identity.serialise() for identity in self._node.db.get_all_identities().values()]
        )

    @request_manager.handle_request(identity_schema)
    def get_identity(self, iid: str) -> (Response, int):
        identity = self._node.db.get_identity(iid)
        return create_ok_response(
            identity.serialise() if identity else None
        )

    @request_manager.handle_request(None)
    @request_manager.verify_request_body(identity_schema)
    def update_identity(self) -> (Response, int):
        serialised_identity = request_manager.get_request_variable('body')
        self._node.db.update_identity(serialised_identity)
        return create_ok_response()

    @request_manager.handle_request(provenance_schema)
    def get_provenance(self, obj_id: str) -> (Response, int):
        return create_ok_response(self._node.db.get_provenance(obj_id))


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
        serialised_identity = self.get(f"/identity/{iid}")
        return Identity.deserialise(serialised_identity) if serialised_identity else None

    def update_identity(self, identity) -> None:
        self.post('/identity', body=identity.serialise())

    def get_provenance(self, obj_id: str) -> dict:
        return self.get(f"/provenance/{obj_id}")
