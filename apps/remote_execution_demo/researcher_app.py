import os
import sys
import logging
import traceback

from apps.remote_execution_demo.server.helpers import get_keystore
from saas.utilities.general_helpers import prompt

from apps.remote_execution_demo.server.user import UserAgent

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('researcher_app')
logger.info(f"using the following command line arguments: {sys.argv}")


def run_app():
    try:
        datastore_path = os.path.join(os.environ['HOME'], '.datastore_researcher')
        app_rest_address = ('127.0.0.1', 5020)
        node_rest_address = ('127.0.0.1', 5021)
        node_p2p_address = ('127.0.0.1', 4021)

        # initialise the path
        if os.path.isfile(datastore_path):
            raise Exception(f"Keystore path '{datastore_path}' is a file.")

        if not os.path.isdir(datastore_path):
            logger.info(f"creating datastore directory '{datastore_path}'")
            os.makedirs(datastore_path, exist_ok=True)

        # get the keystore and initialise the node
        keystore = get_keystore(datastore_path, password='password')

        user = UserAgent(datastore_path, keystore, app_rest_address, node_rest_address, node_p2p_address)
        user.start_service()

        prompt("Press return to terminate the application.")

        user.stop_service()

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        logger.error(e)


if __name__ == "__main__":
    run_app()
