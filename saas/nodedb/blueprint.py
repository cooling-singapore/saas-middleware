from __future__ import annotations

from typing import Optional, List

from pydantic import BaseModel
from requests import Response

import saas.node
from saas.keystore.identity import Identity
from saas.keystore.schemas import Identity as IdentitySchema
from saas.logging import Logging
from saas.rest.blueprint import SaaSBlueprint, create_ok_response
from saas.rest.proxy import EndpointProxy
from saas.rest.request_manager import request_manager
from saas.schemas import NetworkNode, ObjectProvenance

logger = Logging.get('nodedb.blueprint')
endpoint_prefix = "/api/v1/nodedb"


class NetworkNodeDetail(BaseModel):
    iid = str
    identity: IdentitySchema
    dor_service: bool
    rti_service: bool
    rest_service_address: str
    p2p_service_address: str


class NetworkNodes(BaseModel):
    __root__: List[NetworkNode]


class Identities(BaseModel):
    __root__: List[IdentitySchema]


class NodeDBBlueprint(SaaSBlueprint):
    def __init__(self, node: saas.node.Node):
        super().__init__('nodedb', __name__, endpoint_prefix)
        self._node = node

        self.add_rule('node', self.get_node, methods=['GET'])
        self.add_rule('network', self.get_network, methods=['GET'])
        self.add_rule('identity', self.get_identities, methods=['GET'])
        self.add_rule('identity', self.update_identity, methods=['POST'])
        self.add_rule('identity/<iid>', self.get_identity, methods=['GET'])
        self.add_rule('provenance/<obj_id>', self.get_provenance, methods=['GET'])

    @request_manager.handle_request(NetworkNodeDetail)
    def get_node(self) -> (Response, int):
        p2p_address = self._node.p2p.address()
        rest_address = self._node.rest.address()

        return create_ok_response({
            "iid": self._node.identity.id,
            "identity": self._node.identity.serialise(),
            "dor_service": self._node.dor is not None,
            "rti_service": self._node.rti is not None,
            "rest_service_address": f"{p2p_address[0]}:{p2p_address[1]}",
            "p2p_service_address": f"{rest_address[0]}:{rest_address[1]}" if rest_address else None
        })

    @request_manager.handle_request(NetworkNodes)
    def get_network(self) -> (Response, int):
        return create_ok_response(
            [n.as_dict() for n in self._node.db.get_network_all()]
        )

    @request_manager.handle_request(Identities)
    def get_identities(self) -> (Response, int):
        return create_ok_response(
            [identity.serialise() for identity in self._node.db.get_all_identities().values()]
        )

    @request_manager.handle_request(IdentitySchema)
    def get_identity(self, iid: str) -> (Response, int):
        identity = self._node.db.get_identity(iid)
        return create_ok_response(
            identity.serialise() if identity else None
        )

    @request_manager.handle_request()
    @request_manager.verify_request_body(IdentitySchema)
    def update_identity(self) -> (Response, int):
        serialised_identity = request_manager.get_request_variable('body')
        self._node.db.update_identity(serialised_identity)
        return create_ok_response()

    @request_manager.handle_request(ObjectProvenance)
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
