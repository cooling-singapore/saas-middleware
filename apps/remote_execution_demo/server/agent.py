import json
import os
import shutil
import subprocess
import sys
import logging
from threading import Lock

from werkzeug.utils import secure_filename

from flask import Flask, Blueprint, jsonify, request, send_from_directory
from flask_cors import CORS

from saas.dor.blueprint import DORProxy
from saas.node import Node
from saas.rest.service import FlaskServerThread
from saas.rti.blueprint import RTIProxy
from saas.utilities.general_helpers import load_json_from_file, get_timestamp_now, dump_json_to_file

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger('execution_agent')
logger.info(f"using the following command line arguments: {sys.argv}")

endpoint_prefix = "/api/v1/agent"


class ExecutionAgent:
    def __init__(self, path, keystore, app_rest_address, node_rest_address, node_p2p_address):
        self._lock = Lock()
        self._transactions = {}
        self._workers = {}
        self._next_tid = 0
        self._path = path
        self._app_rest_address = app_rest_address
        self._node_rest_address = node_rest_address

        files_path = os.path.join(self._path, 'files')
        if not os.path.isdir(files_path):
            logger.info(f"creating directory '{files_path}'")
            os.makedirs(files_path, exist_ok=True)

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
        blueprint.add_url_rule('/review/<tx_id>/<obj_name>', self.review.__name__, self.review, methods=['POST'])
        blueprint.add_url_rule('/download/<tx_id>/in/<obj_name>', self.download_input_object.__name__, self.download_input_object, methods=['GET'])
        blueprint.add_url_rule('/download/<tx_id>/out/<obj_name>', self.download_output_object.__name__, self.download_output_object, methods=['GET'])
        blueprint.add_url_rule('/download/<tx_id>/proc', self.download_processor.__name__, self.download_processor, methods=['GET'])
        self._app.register_blueprint(blueprint)

    def start_service(self):
        self._thread = FlaskServerThread(self._app, self._app_rest_address[0], self._app_rest_address[1])
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
                'out_obj_ids': {},
                'review': {},
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

            status = job_info['status']
            is_successful = True
            for obj_name in transaction['out_obj_ids']:
                key = f"output:{obj_name}"
                if key in status:
                    obj_id = status[key]
                    transaction['out_obj_ids'][obj_name] = obj_id
                else:
                    is_successful = False

            if is_successful:
                transaction['status'] = 'done'

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
            dor = DORProxy(self._node_rest_address, self.node.identity())
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
            subprocess.check_output(['git', 'checkout', commit_id], cwd=repo_path)

            descriptor_path = os.path.join(repo_path, path, 'descriptor.json')

            proc_descriptor = load_json_from_file(descriptor_path)
            print(proc_descriptor)
            shutil.rmtree(repo_path)

            git_spec_path = os.path.join(self._path, f"{tx_id}_git_spec.json")
            dump_json_to_file({
                'source': source,
                'commit_id': commit_id,
                'path': path,
                'descriptor': proc_descriptor
            }, git_spec_path)

            dor = DORProxy(self._node_rest_address, self.node.identity())
            rti = RTIProxy(self._node_rest_address, self.node.identity())

            proc_id = dor.add_processor(git_spec_path, self.node.identity(), {
                'created_t': get_timestamp_now(),
                'created_by': 'test_user'
            })
            descriptor = rti.deploy(proc_id)

            self._transactions[tx_id]['proc_id'] = proc_id
            self._transactions[tx_id]['proc_descriptor'] = proc_descriptor

            for item in proc_descriptor['output']:
                self._transactions[tx_id]['out_obj_ids'][item['name']] = None

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
            rti = RTIProxy(self._node_rest_address, self.node.identity())
            job_id = rti.submit_job(proc_id, proc_input, self.node.identity())
            job_id = str(job_id)

            transaction['status'] = 'running'
            transaction['job_id'] = job_id

            return jsonify(job_id), 201

    def review(self, tx_id, obj_name):
        form = request.json if request.json else json.loads(request.form['body'])

        comment = form['comment']
        decision = form['decision']

        # get the transaction details
        with self._lock:
            transaction = self._transactions[tx_id]
            transaction['review'][obj_name] = {
                'released': decision,
                'comment': comment
            }

        return jsonify(), 201

    def _download_object(self, tx_id, category, obj_name):
        # get the transaction details
        with self._lock:
            transaction = self._transactions[tx_id]
            obj_id = transaction[category][obj_name]

            obj_path = os.path.join(self._path, 'files', obj_id)

            dor = DORProxy(self._node_rest_address, self.node.identity())
            dor.get_content(obj_id, self.node.identity(), obj_path)

            # stream the file content
            head, tail = os.path.split(obj_path)
            return send_from_directory(head, tail, as_attachment=True)

    def download_input_object(self, tx_id, obj_name):
        return self._download_object(tx_id, 'in_obj_ids', obj_name)

    def download_output_object(self, tx_id, obj_name):
        return self._download_object(tx_id, 'out_obj_ids', obj_name)

    def download_processor(self, tx_id):
        # get the transaction details
        with self._lock:
            transaction = self._transactions[tx_id]
            obj_id = transaction['proc_id']

            obj_path = os.path.join(self._path, 'files', obj_id)

            dor = DORProxy(self._node_rest_address, self.node.identity())
            dor.get_content(obj_id, self.node.identity(), obj_path)

            # stream the file content
            head, tail = os.path.split(obj_path)
            return send_from_directory(head, tail, as_attachment=True)
