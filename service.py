import os
import json
import logging
import traceback
import argparse

from saas.app import initialise_app
from saas.utilities.general_helpers import get_address_from_string, generate_random_string

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('Service')


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

try:
    datastore_path = os.path.join(os.environ['HOME'], 'saas-node-datastore')
    rest_api_address = '127.0.0.1:5001'
    p2p_server_address = '127.0.0.1:4001'
    boot_node_address = '127.0.0.1:4001'
    node_name = generate_random_string(8)

    parser = argparse.ArgumentParser(description='Start a SaaS node instance.')
    parser.add_argument('--datastore', dest='datastore', action='store', default=datastore_path,
                        help=f"directory for the node to keep all data. Default: '{datastore_path}'")
    parser.add_argument('--rest-api-address', dest='rest-api-address', action='store', default=rest_api_address,
                        help=f"address (host:port) used by the node for the REST API. Default: '{rest_api_address}'")
    parser.add_argument('--p2p-server-address', dest='p2p-server-address', action='store', default=p2p_server_address,
                        help=f"address (host:port) used by the node for the P2P server. Default: '{p2p_server_address}'")
    parser.add_argument('--boot-node-address', dest='boot-node-address', action='store', default=boot_node_address,
                        help=f"address (host:port) of another node in the domain to bootstrap inclusion of this "
                             f"node into the P2P network. Default: '{boot_node_address}'")
    parser.add_argument('--name', dest='node-name', action='store', default=node_name,
                        help=f"the name of this node instance. Default: random hexadecimal string of length 8 (e.g., "
                             f"'{node_name}')")
    parser.add_argument('--password', dest='password', action='store', required=False,
                        help=f"the password used for the node identity.")

    parser.print_help()

    args = parser.parse_args()
    parameters = vars(args)

    rest_url, rest_port = get_address_from_string(parameters['rest-api-address'])

    app = initialise_app(parameters)
    app.run(rest_url, rest_port, debug=False)

    # read saas configuration and initialise the SaaS Middleware saas
    if 'SAAS_CONFIG' in os.environ:
        config_path = os.environ['SAAS_CONFIG']
        if os.path.isfile(config_path):
            with open(config_path) as json_file:
                # load configuration
                logger.info(f"loading configuration from '{config_path}'")
                configuration = json.load(json_file)
                logger.debug(f"configuration: {configuration}")

                rest_url, rest_port = get_address_from_string(configuration['rest-api-address'])

                app = initialise_app(configuration)
                app.run(rest_url, rest_port, debug=False)

        else:
            logger.error(f"configuration file '{config_path}' not found or not a file.")

    else:
        logger.error("environment variable 'SAAS_CONFIG' not found.")

except argparse.ArgumentError:
    parser.print_help()

except Exception as e:
    trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
    logger.error(f"error while executing service: {e}\n{trace}")
