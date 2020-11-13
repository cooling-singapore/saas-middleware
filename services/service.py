import os
import json
import logging

from flask import Flask
from node import Node
from dor import DataObjectRepository

import dor_blueprint

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('Service')
app = Flask(__name__)


# def determine_host():
#     """
#     Returns the endpoint address as string using the public IP address.
#     """
#
#     # based on this: https://stackoverflow.com/a/166589
#     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     s.connect(("8.8.8.8", 80))
#     host = s.getsockname()[0]
#     s.close()
#
#     return host

def create_node_instance(config):
    # is the datastore path defined?
    if 'datastore' not in config:
        raise Exception("'datastore' not defined in configuration")

    # does the directory exist?
    datastore_path = config['datastore']
    if os.path.exists(datastore_path):
        # is it a directory?
        if not os.path.isdir(datastore_path):
            raise Exception("datastore path '{}' exists but is not a directory".format(datastore_path))

        logger.info("using existing datastore directory '{}'".format(datastore_path))

    else:
        logger.info("creating datastore directory '{}'.".format(datastore_path))
        os.makedirs(datastore_path)

    temp = config['server_address']
    temp = temp.split(":")
    server_address = (temp[0], int(temp[1]))
    password = config['password']

    instance = Node(datastore_path)
    instance.initialise_identity(password.encode('utf-8'))
    instance.start_server(server_address)
    return instance


def create_dor_instance(node, config):
    datastore_path = config['datastore']

    # do we have configuration instructions for the service?
    if 'dor' not in config:
        raise Exception("no configuration found for DOR service.")

    # # extract the DOR config and proceed with initialisation
    # config = config['dor']
    #
    # # do we use encryption?
    # if 'encryption_enabled' in config and config['encryption_enabled'] is True:
    #     # do we have a custodian key name
    #     if 'custodian_key' not in config:
    #         raise Exception("'custodian_key' not defined in SaaS DOR config.")
    #
    #     # extract DOR custodian key id
    #     custodian_key = config['custodian_key']
    #     logger.info("SaaS DOR using custodian key '{}'.".format(custodian_key))
    #
    #     # check if we have the public key (needed for encryption and signature verification)
    #     try:
    #         result = subprocess.check_output(['gpg', '--list-keys', custodian_key])
    #         result = result.decode('utf-8')
    #         logger.info("SaaS DOR custodian public key info:\n{}".format(result))
    #     except subprocess.CalledProcessError as e1:
    #         raise Exception("error while checking custodian public key '{}': {}".format(custodian_key, e1))
    #
    #     # check if we have the private key (needed for decryption and signing)
    #     try:
    #         result = subprocess.check_output(['gpg', '--list-secret-keys', custodian_key])
    #         result = result.decode('utf-8')
    #         logger.info("SaaS DOR custodian private key info:\n{}".format(result))
    #     except subprocess.CalledProcessError as e1:
    #         raise Exception("error while checking private key '{}': {}".format(custodian_key, e1))
    #
    #     # create the DOR instance
    #     instance = DataObjectRepository(datastore_path, custodian_key)
    #     logger.info("SaaS DOR instance initialised using datastore '{}' and custodian key '{}'.".format(datastore_path,
    #                                                                                                     custodian_key))
    #
    # else:
    #     # create the DOR instance
    #     instance = DataObjectRepository(datastore_path)
    #     logger.info("SaaS DOR instance initialised WITHOUT encryption using datastore '{}'.".format(datastore_path))

    instance = DataObjectRepository(node, datastore_path)
    dor_blueprint.initialise(instance)

    return instance


try:
    node = None
    dor = None

    # read saas configuration and initialise the SaaS Middleware services
    if 'SAAS_CONFIG' in os.environ:
        config_path = os.environ['SAAS_CONFIG']
        if os.path.isfile(config_path):
            with open(config_path) as json_file:
                # load configuration
                logger.info("loading configuration from '{}'".format(config_path))
                configuration = json.load(json_file)
                logger.debug("configuration: {}".format(configuration))

                # create the node instance
                node = create_node_instance(configuration)
                # node['dor'] = create_dor_instance(node, configuration)
                dor = create_dor_instance(node, configuration)

                # register the SaaS DOR service blueprint
                logger.info("register SaaS Data Object Repository service.")
                app.register_blueprint(dor_blueprint.blueprint, url_prefix='/repository')
                dor_blueprint.initialise(dor)

        else:
            logger.error("configuration file '{}' not found or not a file.".format(config_path))

    else:
        logger.error("environment variable 'SAAS_CONFIG' not found.")

    if __name__ == '__main__':
        app.run('127.0.0.1', 5000, debug=False)

except Exception as e:
    logger.error(e)