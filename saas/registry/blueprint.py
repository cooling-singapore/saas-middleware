"""
Flask blueprint for the SaaS Data Object Repository.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import logging

from flask import Blueprint
from flask_cors import CORS

from saas.utilities.blueprint_helpers import create_signed_response
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
def get_node_info():
    return create_signed_response(node, '/node', 200, {
        "node_address": node.server_address,
        "node_public_key": node.key.public_as_string()
    })


@blueprint.route('/', methods=['GET'])
def get_registry_contents():
    node.registry.get()
    return create_signed_response(node, '/', 200, {
        "contents": node.registry.get()
    })
