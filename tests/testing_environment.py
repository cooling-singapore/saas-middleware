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


def create_authentication(url, auth_key, body=None, attachment_path=None):
    return {
        'public_key': auth_key.public_as_string(),
        'signature':
            auth_key.sign_authentication_token(url, body=body, files=[attachment_path]) if attachment_path else
            auth_key.sign_authentication_token(url, body=body)
    }


def create_authorisation(url, auth_key, body=None):
    return {
        'public_key': auth_key.public_as_string(),
        'signature': auth_key.sign_authorisation_token(url, body)
    }


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
    __instance = None

    @staticmethod
    def get_instance(alternative_config_path=None):
        with threading.Lock():
            if TestingEnvironment.__instance is None:
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
                        TestingEnvironment.__instance = TestingEnvironment(configuration)
                else:
                    raise RuntimeError("Config file '{}' not found/cannot be opened.".format(config_path))

        return TestingEnvironment.__instance

    def __init__(self, configuration):
        self.wd_path = configuration['working-directory']
        self.password = configuration['password']
        self.p2p_host = configuration['p2p-host']
        self.p2p_port = configuration['p2p-port']
        self.rest_api_port = configuration['rest-port']
        self.test_node_config = configuration['test-node-config']
        self.app = None
        self.app_service = None
        self.app_service_p2p_host = None
        self.app_service_p2p_port = None

    def prepare_working_directory(self, wd_path=None):
        home = str(Path.home())
        wd_path = wd_path if wd_path else self.wd_path

        # ensure that the testing path is in the users home directory
        logger.info("home: {}".format(home))
        logger.info("wd  : {}".format(self.wd_path))
        if not self.wd_path.startswith(home):
            raise RuntimeError("Working directory '{}' not part of users home '{}'.".format(wd_path, home))

        # ensure that the testing working directory is at least two levels down (to reduce the risk of unintentionally
        # deleting top-level / higher level user directories. NOT BULLET PROOF.
        n_home = home.count(os.path.sep)
        n_wd = wd_path.count(os.path.sep)
        logger.info("directory levels: home={}, wd={}".format(n_home, n_wd))
        if not n_wd > n_home + 2:
            raise RuntimeError("Working directory '{}' too high up in the directory hierarchy of the users home '{}'".format(wd_path, home))

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

    def generate_keys(self, n):
        keys = []
        for i in range(0, n):
            path = os.path.join(self.wd_path, "key_{}.pem".format(i))
            if os.path.isfile(path):
                key = ECKeyPair.from_private_key_file(path, self.password)
            else:
                key = ECKeyPair.create_new()
                key.write_private(path, self.password)
            keys.append(key)

        return keys

    def start_flask_app(self):
        self.prepare_working_directory(self.test_node_config['datastore'])

        rest_url, rest_port = get_address_from_string(self.test_node_config['rest-address'])
        app = initialise_app(self.test_node_config)

        self.app_service_p2p_host, self.app_service_p2p_port = get_address_from_string(
            self.test_node_config['p2p-server-address']
        )

        self.app_service = FlaskServerThread(app, rest_url, rest_port)
        self.app_service.start()

    def stop_flask_app(self):
        self.app_service.shutdown()
