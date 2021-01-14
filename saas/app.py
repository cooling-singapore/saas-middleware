import os
import logging

from flask import Flask

from saas.node import Node
from saas.utilities.general_helpers import get_address_from_string

import saas.dor.blueprint as dor_blueprint
import saas.rti.blueprint as rti_blueprint
import saas.registry.blueprint as registry_blueprint

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('App')


def create_node_instance(configuration):
    # is the datastore path defined?
    if 'datastore' not in configuration:
        raise Exception("'datastore' not defined in configuration")

    # does the directory exist?
    datastore_path = configuration['datastore']
    if os.path.exists(datastore_path):
        # is it a directory?
        if not os.path.isdir(datastore_path):
            raise Exception(f"datastore path '{datastore_path}' exists but is not a directory")

        logger.info(f"using existing datastore directory '{datastore_path}'")

    else:
        logger.info(f"creating datastore directory '{datastore_path}'.")
        os.makedirs(datastore_path)

    p2p_server_address = get_address_from_string(configuration['p2p-server-address'])
    boot_node_address = get_address_from_string(configuration['boot-node-address'])
    rest_api_address = get_address_from_string(configuration['rest-api-address'])

    instance = Node(configuration['name'], datastore_path, rest_api_address)
    instance.initialise_identity(configuration['password'])
    instance.start_server(p2p_server_address)
    instance.initialise_registry(boot_node_address)

    return instance


def initialise_app(configuration):
    # create the node instance
    node = create_node_instance(configuration)

    # create the Flask app
    app = Flask(__name__)

    # register the registry blueprint
    logger.info("register SaaS Node Registry service.")
    app.register_blueprint(registry_blueprint.blueprint, url_prefix='/registry')
    registry_blueprint.initialise(node)

    # register the DOR blueprint
    logger.info("register SaaS Data Object Repository service.")
    app.register_blueprint(dor_blueprint.blueprint, url_prefix='/repository')
    dor_blueprint.initialise(node)

    # register the RTI blueprint
    logger.info("register SaaS Runtime Infrastructure service.")
    app.register_blueprint(rti_blueprint.blueprint, url_prefix='/processor')
    rti_blueprint.initialise(node)

    return app
