import logging
import threading

from flask import Flask
from flask_cors import CORS
from werkzeug.serving import make_server

from saas.utilities.blueprint_helpers import request_manager

logger = logging.getLogger('rest.service')


class FlaskServerThread(threading.Thread):
    def __init__(self, app, host, port):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.srv = make_server(host, port, app, threaded=True)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        logger.info("Flask server thread running")
        self.srv.serve_forever()
        logger.info("Flask server thread terminated")

    def shutdown(self):
        self.srv.shutdown()


class RESTService:
    def __init__(self, node, address):
        self._node = node
        self._address = address
        self._app = Flask(__name__)
        CORS(self._app, resources={r"/api/*": {"origins": "*"}})
        request_manager.init_app(self._app, self._node)

        self._thread = None

    def address(self):
        return self._address

    def add(self, blueprint):
        self._app.register_blueprint(blueprint)

    def start_service(self):
        self._thread = FlaskServerThread(self._app, self._address[0], self._address[1])
        self._thread.start()

    def stop_service(self):
        if self._thread:
            self._thread.shutdown()
