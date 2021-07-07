import logging

from saas.keystore.keystore import Identity
from saas.rest.proxy import EndpointProxy

from flask import Blueprint, jsonify

from saas.utilities.blueprint_helpers import request_manager

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
        result = {}
        for iid, identity in self._node.db.get_all_identities().items():
            result[iid] = identity.serialise()

        return jsonify(result), 200

    def get_identity(self, iid):
        identity = self._node.db.get_identity(iid=iid)
        if identity is not None:
            return jsonify(identity.serialise()), 200

        else:
            return jsonify(f"No identity with id {iid} found."), 404

    @request_manager.authentication_required
    @request_manager.verify_request_body(update_identity_body_specification)
    def update_identity(self):
        body = request_manager.get_request_variable('body')
        identity = body['identity']
        signature = body['signature']

        # update the node db
        if self._node.db.update_identity(identity, signature):
            return jsonify(identity), 200

        else:
            return jsonify(f"Identity not updated (either outdated record invalid signature)."), 405


class NodeDBProxy(EndpointProxy):
    def __init__(self, remote_address, sender):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address, sender)

    def get_node(self):
        r = self.get("/node")
        return r['reply']

    def get_network(self):
        r = self.get("/network")
        return r['reply']

    def get_identities(self):
        r = self.get("/identity")
        return r['reply']

    def get_identity(self, iid):
        r = self.get(f"/identity/{iid}")
        return r['reply']

    def update_identity(self, identity, signature):
        body = {
            'identity': identity.serialise(),
            'signature': signature
        }

        r = self.post('/identity', body=body)
        return r['reply'] if 'reply' in r else r
