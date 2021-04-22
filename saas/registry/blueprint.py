"""
Flask blueprint for the SaaS Data Object Repository.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging

from flask import Blueprint, jsonify
from flask_cors import CORS

from saas.utilities.blueprint_helpers import request_manager
from saas.node import Node

# create the blueprint object and allows CORS for the processor route
blueprint = Blueprint('registry', __name__)
CORS(blueprint)

logger = logging.getLogger('Registry.Blueprint')
node: Node


def initialise(node_instance):
    global node
    node = node_instance


@blueprint.route('/node', methods=['GET'])
@request_manager.authentication_required
def get_node_info():
    return jsonify({
        "iid": node.key.iid,
        "public_key": node.key.public_as_string(),
        "rest_address": node.rest_api_address,
        "p2p_address": node.server_address
    }), 200


@blueprint.route('', methods=['GET'])
@request_manager.authentication_required
def get_registry_contents():
    return jsonify({
        "contents": node.registry.get()
    }), 200
