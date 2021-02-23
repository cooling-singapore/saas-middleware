import os
import json
import threading
import logging
import subprocess

from pathlib import Path
from werkzeug.serving import make_server

from saas.app import initialise_app
from saas.eckeypair import ECKeyPair
from saas.utilities.general_helpers import get_address_from_string

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


class FlaskServerThread(threading.Thread):
    def __init__(self, app, url, port):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.srv = make_server(url, port, app, threaded=True)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        logger.info("Flask server thread running")
        self.srv.serve_forever()
        logger.info("Flask server thread terminated")

    def shutdown(self):
        self.srv.shutdown()


class TestingEnvironment:
    _instance = None
    _lock: threading.Lock = threading.Lock()

    @staticmethod
    def get_instance(alternative_config_path=None):
        with TestingEnvironment._lock:
            if TestingEnvironment._instance is None:
                if 'SAAS_TEST_CONFIG' not in os.environ:
                    logger.warning("No config file specified in environment variable SAAS_TEST_CONFIG.")
                    if not alternative_config_path:
                        logger.warning("No alternative config path specified either.")
                        raise RuntimeError('No config file path specified.')
                    else:
                        config_path = alternative_config_path

                else:
                    config_path = os.environ['SAAS_TEST_CONFIG']

                if os.path.isfile(config_path):
                    with open(config_path) as json_file:
                        configuration = json.load(json_file)
                        TestingEnvironment._instance = TestingEnvironment(configuration)
                else:
                    raise RuntimeError(f"Config file '{config_path}' not found/cannot be opened.")

        return TestingEnvironment._instance

    def __init__(self, configuration):
        self.wd_path = configuration['working-directory']
        self.password = configuration['password']
        self.p2p_server_address = get_address_from_string(configuration['p2p-server-address'])
        self.rest_api_address = get_address_from_string(configuration['rest-api-address'])
        self.test_node_config = configuration['test-node-config']

        self.app = None
        self.app_service = None
        self.app_service_p2p_host = None
        self.app_service_p2p_port = None
        self.app_wd_path = None

    def prepare_working_directory(self, wd_path=None):
        home = str(Path.home())
        wd_path = wd_path if wd_path else self.wd_path

        # ensure that the testing path is in the users home directory
        logger.info(f"home: {home}")
        logger.info(f"wd  : {self.wd_path}")
        if not self.wd_path.startswith(home):
            raise RuntimeError(f"Working directory '{wd_path}' not part of users home '{home}'.")

        # ensure that the testing working directory is at least two levels down (to reduce the risk of unintentionally
        # deleting top-level / higher level user directories. NOT BULLET PROOF.
        n_home = home.count(os.path.sep)
        n_wd = wd_path.count(os.path.sep)
        logger.info(f"directory levels: home={n_home}, wd={n_wd}")
        if not n_wd > n_home + 2:
            raise RuntimeError(f"Working directory '{wd_path}' too high up in the "
                               f"directory hierarchy of the users home '{home}'")

        # delete the whole testing working directory (if it exists) and recreate it
        subprocess.check_output(['rm', '-rf', wd_path])
        subprocess.check_output(['mkdir', '-p', wd_path])

    def generate_random_file(self, filename, size):
        path = os.path.join(self.wd_path, filename)
        with open(path, 'wb') as f:
            f.write(os.urandom(int(size)))
        return path

    def generate_zero_file(self, filename, size):
        path = os.path.join(self.wd_path, filename)
        with open(path, 'wb') as f:
            f.write(b"\0" * int(size))
        return path

    def create_file_with_content(self, filename, content):
        path = os.path.join(self.wd_path, filename)
        with open(path, 'w') as f:
            f.write(content)
        return path

    def generate_keys(self, n):
        keys = []
        for i in range(0, n):
            path = os.path.join(self.wd_path, f"key_{i}.pem")
            if os.path.isfile(path):
                key = ECKeyPair.from_private_key_file(path, self.password)
            else:
                key = ECKeyPair.create_new()
                key.write_private(path, self.password)
            keys.append(key)

        return keys

    def start_flask_app(self):
        self.app_wd_path = self.test_node_config['datastore']
        self.prepare_working_directory(self.app_wd_path)

        rest_url, rest_port = get_address_from_string(self.test_node_config['rest-api-address'])
        app = initialise_app(self.test_node_config)

        self.app_service_p2p_host, self.app_service_p2p_port = get_address_from_string(
            self.test_node_config['p2p-server-address']
        )

        self.app_service = FlaskServerThread(app, rest_url, rest_port)
        self.app_service.start()

    def stop_flask_app(self):
        self.app_service.shutdown()
