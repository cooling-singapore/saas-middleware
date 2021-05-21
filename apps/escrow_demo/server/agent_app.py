import json
import os
import shutil
import subprocess
import sys
import logging
import time
import traceback
from threading import Lock, Thread

from werkzeug.utils import secure_filename

from apps.escrow_demo.server.helpers import get_keystore

from flask import Flask, Blueprint, jsonify, request, render_template
from flask_cors import CORS

from saas.dor.blueprint import DORProxy
from saas.node import Node
from saas.rest.service import FlaskServerThread
from saas.rti.blueprint import RTIProxy
from saas.rti.status import State
from saas.utilities.general_helpers import prompt, load_json_from_file, get_timestamp_now, dump_json_to_file

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('escrow_demo')
logger.info(f"using the following command line arguments: {sys.argv}")

app_rest_address = ('127.0.0.1', 5010)
node_rest_address = ('127.0.0.1', 5011)
node_p2p_address = ('127.0.0.1', 4011)
endpoint_prefix = "/api/v1/agent"


class Worker(Thread):
    def __init__(self, node, t):
        super().__init__()
        self.node = node
        self.t = t

        self.job_id = None

    def run(self):
        if not self.node.rti.is_deployed(self.t['proc_id']):
            self.node.rti.deploy(self.t['proc_id'])

        proc_input = [
            {
                'name': 'input',
                'type': 'reference',
                'obj_id': self.t['in_obj_id']
            }
        ]

        job_id = self.node.rti.submit_job(self.t['proc_id'], proc_input, self.node.identity())
        logger.info(f"job_id={job_id}")
        assert(job_id is not None)

        # wait for job to be done
        while True:
            time.sleep(5)
            descriptor, status = self.node.get_job_info(self.t['proc_id'], self.job_id)
            if descriptor and status:
                logger.info(f"descriptor={descriptor}")
                logger.info(f"status={status}")

                state = State.from_string(status['state'])
                if state == State.SUCCESSFUL:
                    break
                elif state == State.FAILED:
                    raise RuntimeError('Job failed')


class EscrowAgent:
    def __init__(self, path, password=None):
        self._lock = Lock()
        self._transactions = {}
        self._workers = {}
        self._next_tid = 0
        self._path = path

        # initialise the path
        if os.path.isfile(path):
            raise Exception(f"Keystore path '{path}' is a file.")

        if not os.path.isdir(path):
            logger.info(f"creating keystore directory '{path}'")
            os.makedirs(self._path, exist_ok=True)
            os.makedirs(os.path.join(self._path, 'files'), exist_ok=True)

        # get the keystore and initialise the node
        keystore = get_keystore(path, password)

        self.node = Node(keystore, path)
        self.node.startup(node_p2p_address)
        self.node.start_dor_service()
        self.node.start_rti_service()
        self.node.start_rest_service(node_rest_address)

        self._thread = None
        self._app = Flask(__name__)
        CORS(self._app, resources={r"/api/*": {"origins": "*"}})

        # create and register blueprint
        blueprint = Blueprint('agent', __name__, url_prefix=endpoint_prefix)
        blueprint.add_url_rule('/identity', self.get_identity.__name__, self.get_identity, methods=['GET'])
        blueprint.add_url_rule('/transaction', self.add_transaction.__name__, self.add_transaction, methods=['POST'])
        blueprint.add_url_rule('/transaction/<tx_id>', self.get_transaction.__name__, self.get_transaction, methods=['GET'])
        blueprint.add_url_rule('/transaction', self.get_transactions.__name__, self.get_transactions, methods=['GET'])
        blueprint.add_url_rule('/confirm/<tx_id>/input', self.confirm_input.__name__, self.confirm_input, methods=['POST'])
        blueprint.add_url_rule('/confirm/<tx_id>/processor', self.confirm_processor.__name__, self.confirm_processor, methods=['POST'])
        blueprint.add_url_rule('/confirm/<tx_id>/execute', self.confirm_execute.__name__, self.confirm_execute, methods=['POST'])
        self._app.register_blueprint(blueprint)

    def start_service(self, address):
        self._thread = FlaskServerThread(self._app, address[0], address[1])
        self._thread.start()

    def stop_service(self):
        self.node.shutdown()

        if self._thread:
            self._thread.shutdown()

    def get_identity(self):
        result = {
            'id': self.node.id(),
            'name': self.node.name(),
            'email': self.node.email(),
            'public_key': self.node.identity().public_as_string()
        }
        return jsonify(result), 200

    def add_transaction(self):
        form = request.json if request.json else json.loads(request.form['body'])

        provider = self.node.db.get_identity_record(form['provider_iid'])
        consumer = self.node.db.get_identity_record(form['consumer_iid'])

        with self._lock:
            tid = str(self._next_tid)
            self._transactions[tid] = {
                'id': tid,
                'name': form['name'],
                'description': form['description'],
                'provider_iid': provider.iid,
                'provider_pubkey': provider.public_key,
                'consumer_iid': consumer.iid,
                'consumer_pubkey': consumer.public_key,
                'review_algorithm': form['review_algorithm'],
                'review_output': form['review_output'],
                'proc_id': None,
                'proc_descriptor': None,
                'in_obj_ids': {},
                'out_obj_id': None,
                'status': 'initialised'
            }
            self._next_tid += 1
            return jsonify(self._transactions[tid]), 201

    def get_transactions(self):
        with self._lock:
            result = {}
            for tx_id in self._transactions:
                result[tx_id] = self._get_transaction(tx_id)
            return jsonify(result), 200

    def _get_transaction(self, tx_id):
        transaction = self._transactions[tx_id]

        if 'job_id' in transaction:
            job_info = self.node.rti.get_job_info(transaction['job_id'])
            transaction['job_info'] = job_info

        provider_record = self.node.db.get_identity_record(transaction['provider_iid'])
        consumer_record = self.node.db.get_identity_record(transaction['consumer_iid'])
        result = {
            'agent': {
                'id': self.node.id(),
                'name': self.node.name(),
                'email': self.node.email()
            },
            'provider': {
                'id': transaction['provider_iid'],
                'name': provider_record.name,
                'email': provider_record.email
            },
            'consumer': {
                'id': transaction['consumer_iid'],
                'name': consumer_record.name,
                'email': consumer_record.email
            },
            'transaction': transaction
        }
        return result

    def get_transaction(self, tx_id):
        with self._lock:
            result = self._get_transaction(tx_id)
            return jsonify(result), 200

    def confirm_input(self, tx_id):
        form = request.json if request.json else json.loads(request.form['body'])

        # save the file
        f = request.files['attachment']
        path = os.path.join(self._path, 'files', secure_filename(f.filename))
        f.save(path)

        # get the transaction details
        with self._lock:
            dor = DORProxy(node_rest_address, self.node.identity())
            obj_name = form['obj_name']
            data_type = form['data_type']
            data_format = form['data_format']
            obj_id = dor.add_data_object(path, self.node.identity(), data_type, data_format, self.node.name())

            transaction = self._transactions[tx_id]
            transaction['in_obj_ids'][obj_name] = obj_id

            # check if all data objects have been uploaded
            if len(transaction['in_obj_ids']) == len(transaction['proc_descriptor']['input']):
                transaction['status'] = 'ready'

            os.remove(path)
            return jsonify(obj_id), 201

    def confirm_processor(self, tx_id):
        form = request.json if request.json else json.loads(request.form['body'])

        # get the transaction details
        with self._lock:
            # clone the whole repo - just to get the descriptor.json
            source = form['source']
            commit_id = form['commit_id']
            path = form['path']

            repo_path = os.path.join(self._path, tx_id)
            subprocess.check_output(['git', 'clone', source, repo_path])

            temp = os.curdir
            os.chdir(repo_path)
            subprocess.check_output(['git', 'checkout', commit_id])

            descriptor_path = os.path.join(repo_path, path, 'descriptor.json')

            proc_descriptor = load_json_from_file(descriptor_path)
            print(proc_descriptor)

            git_spec_path = os.path.join(self._path, f"{tx_id}_git_spec.json")
            dump_json_to_file({
                'source': source,
                'commit_id': commit_id,
                'path': path,
                'descriptor': proc_descriptor
            }, git_spec_path)

            dor = DORProxy(node_rest_address, self.node.identity())
            rti = RTIProxy(node_rest_address, self.node.identity())

            proc_id = dor.add_processor(git_spec_path, self.node.identity(), {
                'created_t': get_timestamp_now(),
                'created_by': 'test_user'
            })
            descriptor = rti.deploy(proc_id)

            os.chdir(temp)
            shutil.rmtree(repo_path)

            self._transactions[tx_id]['proc_id'] = proc_id
            self._transactions[tx_id]['proc_descriptor'] = proc_descriptor

            return jsonify({
                'proc_id': proc_id,
                'descriptor': proc_descriptor
            }), 201

    def confirm_execute(self, tx_id):
        # get the transaction details
        with self._lock:
            transaction = self._transactions[tx_id]

            proc_input = []
            for item in transaction['proc_descriptor']['input']:
                name = item['name']
                obj_id = transaction['in_obj_ids'][name]

                proc_input.append({
                    'name': name,
                    'type': 'reference',
                    'obj_id': obj_id
                })

            print(proc_input)
            proc_id = transaction['proc_id']
            rti = RTIProxy(node_rest_address, self.node.identity())
            job_id = rti.submit_job(proc_id, proc_input, self.node.identity())
            job_id = str(job_id)

            transaction['status'] = 'running'
            transaction['job_id'] = job_id

            return jsonify(job_id), 201


def run_app():
    try:
        path = os.path.join(os.environ['HOME'], '.datastore_escrow')
        agent = EscrowAgent(path, 'password')
        agent.start_service(app_rest_address)

        prompt("Press return to terminate the agent.")

        agent.stop_service()

    except Exception as e:
        trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
        print(trace)
        logger.error(e)


if __name__ == "__main__":
    run_app()
