import os
import json
import logging

from saas.app import initialise_app
from saas.utilities.general_helpers import get_address_from_string

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


except Exception as e:
    logger.error(e)
