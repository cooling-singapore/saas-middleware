import logging

from saas.rest.proxy import EndpointProxy

from flask import Blueprint, jsonify


logger = logging.getLogger('nodedb.blueprint')
endpoint_prefix = "/api/v1/nodedb"


class NodeDBBlueprint:
    def __init__(self, node):
        self._node = node

    def blueprint(self):
        blueprint = Blueprint('nodedb', __name__, url_prefix=endpoint_prefix)
        blueprint.add_url_rule('/node', self.get_node.__name__, self.get_node, methods=['GET'])
        blueprint.add_url_rule('/network', self.get_network.__name__, self.get_network, methods=['GET'])
        blueprint.add_url_rule('/identities', self.get_identities.__name__, self.get_identities, methods=['GET'])
        return blueprint

    def get_node(self):
        return jsonify({
            "iid": self._node.id(),
            "name": self._node.name(),
            "public_key": self._node.identity().public_as_string(),
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
        for record in self._node.db.get_identity_record():
            result.append({
                'iid': record.iid,
                'public_key': record.public_key,
                'name': record.name,
                'email': record.email,
                'nonce': record.nonce,
                'signature': record.signature
            })

        return jsonify(result), 200


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
        r = self.get("/identities")
        return r['reply']
