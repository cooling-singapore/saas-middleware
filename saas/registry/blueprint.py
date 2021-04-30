import logging

from saas.rest.proxy import EndpointProxy
from saas.utilities.blueprint_helpers import request_manager

from flask import Blueprint, jsonify
from flask_cors import CORS


logger = logging.getLogger('registry.blueprint')
endpoint_prefix = "/api/v1/registry"


class RegistryBlueprint:
    def __init__(self, node):
        self._node = node

    def blueprint(self):
        # create the blueprint and allow CORS for the processor route
        blueprint = Blueprint('registry', __name__, url_prefix=endpoint_prefix)
        blueprint.add_url_rule('/node', self.get_node_info.__name__, self.get_node_info, methods=['GET'])
        blueprint.add_url_rule('', self.get_registry_contents.__name__, self.get_registry_contents, methods=['GET'])
        CORS(blueprint)
        return blueprint

    @request_manager.authentication_required
    def get_node_info(self):
        return jsonify({
            "iid": self._node.id(),
            "public_key": self._node.identity().public_as_string(),
            "rest_service_address": self._node.rest.address(),
            "p2p_service_address": self._node.p2p.address()
        }), 200

    @request_manager.authentication_required
    def get_registry_contents(self):
        return jsonify({
            "contents": self._node.registry.get()
        }), 200


class RegistryProxy(EndpointProxy):
    def __init__(self, remote_address, sender):
        EndpointProxy.__init__(self, endpoint_prefix, remote_address, sender)

    def get_node_info(self):
        r = self.get("/node")
        return r['reply']

    def get_registry_contents(self):
        r = self.get("")
        return r['reply']['contents']

