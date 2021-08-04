import logging

from saas.keystore.keystore import Identity
from saas.rest.proxy import EndpointProxy

from flask import Blueprint, jsonify

from saas.rest.request_manager import request_manager

logger = logging.getLogger('nodedb.blueprint')
endpoint_prefix = "/api/v1/nodedb"

update_identity_body_specification = {
    'type': 'object',
    'properties': {
        'identity': Identity.specification,
        'signature': {'type': 'string'}
    },
    'required': ['identity', 'signature']
}


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
            "iid": self._node.identity().id(),
            "identity": self._node.identity().serialise(),
            "rest_service_address": self._node.rest.address(),
            "p2p_service_address": self._node.p2p.address()
        }), 200

    def get_network(self):
        result = []
        for record in self._node.db.get_network():
            result.append({
                'iid': record.iid,
                'last_seen': record.last_seen,
                'p2p_address': record.p2p_address,
                'rest_address': record.rest_address
            })

        return jsonify(result), 200

    def get_identities(self):
        result = []
        for iid, info in self._node.db.get_all_identities().items():
            result.append({
                'iid': iid,
                'identity': info.serialise()
            })

        return jsonify(result), 200

    def get_identity(self, iid):
        identity = self._node.db.get_identity(iid=iid)
        if identity is not None:
            return jsonify(identity.serialise()), 200

        else:
            return jsonify(f"Identity {iid} not found"), 404

    @request_manager.verify_request_body(update_identity_body_specification)
    def update_identity(self):
        body = request_manager.get_request_variable('body')
        identity = body['identity']
        signature = body['signature']

        if self._node.db.update_identity(identity, signature):
            return jsonify(identity), 200

        else:
            return jsonify(f"Database not updated (either outdated record or invalid signature)."), 405


class NodeDBProxy(EndpointProxy):
    def __init__(self, remote_address):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address)

    def get_node(self):
        code, r = self.get("/node")
        return r

    def get_network(self):
        code, r = self.get("/network")
        return r

    def get_identities(self):
        code, r = self.get("/identity")
        identities = {}
        for record in r:
            identity = Identity.deserialise(record['identity'])
            identities[identity.id()] = identity
        return identities

    def get_identity(self, iid):
        code, r = self.get(f"/identity/{iid}")
        return r

    def update_identity(self, identity, signature):
        body = {
            'identity': identity.serialise(),
            'signature': signature
        }

        code, r = self.post('/identity', body=body)
        return r
