import os
import sys
import logging
import traceback
from threading import Lock

from flask import Flask, jsonify, Blueprint, request, render_template, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

from apps.escrow_demo.server.helpers import get_keystore
from saas.node import Node
from saas.rest.service import FlaskServerThread
from saas.utilities.general_helpers import prompt

from agent_proxy import AgentProxy
from saas.dor.blueprint import DORProxy

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('escrow_demo')
logger.info(f"using the following command line arguments: {sys.argv}")

app_rest_address = ('127.0.0.1', 5020)
node_rest_address = ('127.0.0.1', 5021)
node_p2p_address = ('127.0.0.1', 4021)
endpoint_prefix = "/api/v1/user"


class EscrowUser:
    def __init__(self, path, password=None):
        self._lock = Lock()
        self._path = path

        # initialise the path
        if os.path.isfile(path):
            raise Exception(f"Keystore path '{path}' is a file.")

        if not os.path.isdir(path):
            logger.info(f"creating keystore directory '{path}'")
            os.makedirs(self._path, exist_ok=True)
            os.makedirs(os.path.join(self._path, 'files'), exist_ok=True)

        # get the keystore and initialise the node
        keystore = get_keystore(path, password=password)
        self.node = Node(keystore, path)
        self.node.startup(node_p2p_address)
        self.node.start_rest_service(node_rest_address)

        self._thread = None
        self._app = Flask(__name__)
        CORS(self._app, resources={r"/api/*": {"origins": "*"}})

        # create and register blueprint
        blueprint = Blueprint('user', __name__, url_prefix=endpoint_prefix)
        blueprint.add_url_rule('/view_home', self.view_home.__name__, self.view_home, methods=['GET'])
        blueprint.add_url_rule('/view_transaction/<tx_id>', self.view_transaction.__name__, self.view_transaction, methods=['GET'])
        blueprint.add_url_rule('/identity', self.get_identity.__name__, self.get_identity, methods=['GET'])
        blueprint.add_url_rule('/connect', self.connect.__name__, self.connect, methods=['GET'])
        blueprint.add_url_rule('/upload_input', self.upload_input.__name__, self.upload_input, methods=['POST'])
        blueprint.add_url_rule('/deploy_processor', self.deploy_processor.__name__, self.deploy_processor, methods=['POST'])
        blueprint.add_url_rule('/run_processor', self.run_processor.__name__, self.run_processor, methods=['POST'])
        blueprint.add_url_rule('/review', self.review.__name__, self.review, methods=['POST'])
        self._app.register_blueprint(blueprint)

    def start_service(self, address):
        self._thread = FlaskServerThread(self._app, address[0], address[1])
        self._thread.start()

    def stop_service(self):
        self.node.shutdown()

        if self._thread:
            self._thread.shutdown()

    def view_home(self):
        result = render_template("home.html", app_address=f"{app_rest_address[0]}:{app_rest_address[1]}")
        return result

    def view_transaction(self, tx_id):
        host = request.args.get('host')
        port = request.args.get('port')

        result = render_template("transaction.html", tx_id=tx_id,
                                 app_address=f"{app_rest_address[0]}:{app_rest_address[1]}",
                                 agent_address=f"{host}:{port}")
        return result

    def get_identity(self):
        result = {
            'id': self.node.id(),
            'name': self.node.name(),
            'email': self.node.email(),
            'public_key': self.node.identity().public_as_string()
        }
        return jsonify(result), 200

    def connect(self):
        host = request.args.get('host')
        port = request.args.get('port')
        p2p_address = (host, port)

        if self.node.join_network(p2p_address):
            result = {}
            for record in self.node.db.get_identity_record():
                result[record.iid] = {
                    'name': record.name,
                    'email': record.email
                }
            return jsonify(result), 200

        else:
            return jsonify(f"Cannot connect to agent at {host}:{port}"), 500

    def upload_input(self):
        # save the file
        f = request.files['file']
        path = os.path.join(self._path, 'files', secure_filename(f.filename))
        f.save(path)

        agent_address = request.form['agent_address'].split(":")
        tx_id = request.form['tx_id']
        agent = AgentProxy(agent_address, self.node.identity())
        obj_id = agent.confirm_input(tx_id, request.form['obj_name'], request.form['data_type'], request.form['data_format'], path)

        os.remove(path)

        return render_template("transaction.html", tx_id=tx_id,
                               app_address=f"{app_rest_address[0]}:{app_rest_address[1]}",
                               agent_address=f"{agent_address[0]}:{agent_address[1]}")

    def deploy_processor(self):
        agent_address = request.form['agent_address'].split(":")
        tx_id = request.form['tx_id']
        source = request.form['source']
        commit_id = request.form['commit_id']
        path = request.form['path']
        agent = AgentProxy(agent_address, self.node.identity())
        obj_id = agent.confirm_processor(tx_id, source, commit_id, path)

        return render_template("transaction.html", tx_id=tx_id,
                               app_address=f"{app_rest_address[0]}:{app_rest_address[1]}",
                               agent_address=f"{agent_address[0]}:{agent_address[1]}")

    def run_processor(self):
        agent_address = request.form['agent_address'].split(":")
        tx_id = request.form['tx_id']
        agent = AgentProxy(agent_address, self.node.identity())
        job_id = agent.confirm_execute(tx_id)

        return render_template("transaction.html", tx_id=tx_id,
                               app_address=f"{app_rest_address[0]}:{app_rest_address[1]}",
                               agent_address=f"{agent_address[0]}:{agent_address[1]}")

    def review(self):
        agent_address = request.form['agent_address'].split(":")
        tx_id = request.form['tx_id']
        obj_name = request.form['obj_name']
        comment = request.form['comment']
        decision = request.form['decision'] == 'Release'

        agent = AgentProxy(agent_address, self.node.identity())
        agent.review(tx_id, obj_name, comment, decision)

        return render_template("transaction.html", tx_id=tx_id,
                               app_address=f"{app_rest_address[0]}:{app_rest_address[1]}",
                               agent_address=f"{agent_address[0]}:{agent_address[1]}")

def run_app():
    try:
        path = os.path.join(os.environ['HOME'], '.datastore_user')
        agent = EscrowUser(path, 'password')
        agent.start_service(app_rest_address)

        prompt("Press return to terminate the agent.")

        agent.stop_service()

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        logger.error(e)


if __name__ == "__main__":
    run_app()


