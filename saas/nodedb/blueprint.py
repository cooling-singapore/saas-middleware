import logging
from typing import Optional

from saas.keystore.identity import Identity
from saas.keystore.schemas import identity_schema
from saas.nodedb.exceptions import InvalidIdentityError
from saas.rest.proxy import EndpointProxy

from flask import Blueprint, jsonify

from saas.rest.request_manager import request_manager

logger = logging.getLogger('nodedb.blueprint')
endpoint_prefix = "/api/v1/nodedb"


class NodeDBBlueprint:
    def __init__(self, node):
        self._node = node

    def blueprint(self):
        blueprint = Blueprint('nodedb', __name__, url_prefix=endpoint_prefix)
        blueprint.add_url_rule('/node', self.get_node.__name__, self.get_node, methods=['GET'])
        blueprint.add_url_rule('/network', self.get_network.__name__, self.get_network, methods=['GET'])
        blueprint.add_url_rule('/identity', self.get_identities.__name__, self.get_identities, methods=['GET'])
        blueprint.add_url_rule('/identity', self.update_identity.__name__, self.update_identity, methods=['POST'])
        blueprint.add_url_rule('/identity/<iid>', self.get_identity.__name__, self.get_identity, methods=['GET'])
        return blueprint

    def get_node(self):
        return jsonify({
            "iid": self._node.identity().id,
            "identity": self._node.identity().serialise(),
            "dor_service": self._node.dor is not None,
            "rti_service": self._node.rti is not None,
            "rest_service_address": self._node.rest.address(),
            "p2p_service_address": self._node.p2p.address()
        }), 200

    def get_network(self):
        result = self._node.db.get_network()
        return jsonify(result), 200

    def get_identities(self):
        result = [identity.serialise() for identity in self._node.db.get_all_identities().values()]
        return jsonify(result), 200

    def get_identity(self, iid: str):
        identity = self._node.db.get_identity(iid)
        if identity is not None:
            return jsonify(identity.serialise()), 200

        else:
            return jsonify(f"No identity with id {iid} found."), 404

    @request_manager.verify_request_body(identity_schema)
    def update_identity(self):
        serialised_identity = request_manager.get_request_variable('body')

        try:
            self._node.db.update_identity(serialised_identity)
            return jsonify({}), 200

        except InvalidIdentityError:
            return jsonify({
                'reason': 'Invalid identity signature.'
            }), 400


class NodeDBProxy(EndpointProxy):
    def __init__(self, remote_address):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address)

    def get_node(self) -> dict:
        code, r = self.get("/node")
        return r

    def get_network(self) -> list[dict]:
        code, r = self.get("/network")
        return r

    def get_identities(self) -> dict[str, Identity]:
        code, r = self.get("/identity")

        result = {}
        for content in r:
            identity = Identity.deserialise(content)
            result[identity.id] = identity

        return result

    def get_identity(self, iid: str) -> Optional[Identity]:
        code, r = self.get(f"/identity/{iid}")
        return Identity.deserialise(r) if code == 200 else None

    def update_identity(self, identity):
        code, r = self.post('/identity', body=identity.serialise())
        return r
