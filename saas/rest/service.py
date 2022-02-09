import threading

from flask import Flask, Blueprint
from flask_cors import CORS
from saascore.log import Logging
from werkzeug.serving import make_server

from saas.rest.request_manager import request_manager

logger = Logging.get('rest.service')


class FlaskServerThread(threading.Thread):
    def __init__(self, app: Flask, address: (str, int)):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.srv = make_server(address[0], address[1], app, threaded=True)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self) -> None:
        logger.debug("Flask server thread running")
        self.srv.serve_forever()
        logger.debug("Flask server thread terminated")

    def shutdown(self) -> None:
        self.srv.shutdown()


class RESTService:
    def __init__(self, node, address: (str, int)) -> None:
        self._node = node
        self._address = address
        self._app = Flask(__name__)
        CORS(self._app, resources={r"/api/*": {"origins": "*"}})
        request_manager.init_app(self._app, self._node)

        self._thread = None

    def address(self) -> (str, int):
        return self._address

    def add(self, blueprint: Blueprint) -> None:
        self._app.register_blueprint(blueprint)

    def start_service(self) -> None:
        self._thread = FlaskServerThread(self._app, self._address)
        self._thread.start()

    def stop_service(self) -> None:
        if self._thread:
            self._thread.shutdown()
