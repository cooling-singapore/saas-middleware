import os
import sys
import logging
import traceback

from apps.remote_execution_demo.server.helpers import get_keystore
from saas.utilities.general_helpers import prompt

from apps.remote_execution_demo.server.agent import ExecutionAgent
from apps.remote_execution_demo.server.user import UserAgent

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('agency_app')
logger.info(f"using the following command line arguments: {sys.argv}")


def run_app():
    try:
        datastore_path = os.path.join(os.environ['HOME'], '.datastore_agency')
        agent_app_rest_address = ('127.0.0.1', 5000)
        agent_node_rest_address = ('127.0.0.1', 5001)
        agent_node_p2p_address = ('127.0.0.1', 4001)
        user_app_rest_address = ('127.0.0.1', 5010)
        user_node_rest_address = ('127.0.0.1', 5012)
        user_node_p2p_address = ('127.0.0.1', 4012)

        # initialise the path
        if os.path.isfile(datastore_path):
            raise Exception(f"Keystore path '{datastore_path}' is a file.")

        if not os.path.isdir(datastore_path):
            logger.info(f"creating datastore directory '{datastore_path}'")
            os.makedirs(datastore_path, exist_ok=True)

        # get the keystore and initialise the node
        keystore = get_keystore(datastore_path, password='password')

        agent = ExecutionAgent(datastore_path, keystore, agent_app_rest_address, agent_node_rest_address, agent_node_p2p_address)
        agent.start_service()

        user = UserAgent(datastore_path, keystore, user_app_rest_address, user_node_rest_address, user_node_p2p_address)
        user.start_service()

        prompt("Press return to terminate the application.")

        agent.stop_service()
        user.stop_service()

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        logger.error(e)


if __name__ == "__main__":
    run_app()
