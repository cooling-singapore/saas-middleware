import importlib
import json
import os
import sys
from flask import Flask, jsonify, request


def dump_json_to_file(json_input, destination_path):
    """
    Write a given JSON input to a file.
    :param json_input: the JSON input
    :param destination_path: the path of the destination file
    :return: None
    """
    with open(destination_path, 'w') as f:
        json.dump(json_input, f, indent=4, sort_keys=True)

# FIXME: This is directly copied from saas-middleware rti adapters module
class StatusLogger:
    """
    StatusLogger keeps information (key-value pairs) for a job and syncs its contents to disk. This class is
    basically just a wrapper of a dictionary providing convenient functions.
    """

    def __init__(self, path):
        self.path = path
        self.content = {}
        self.update_all({
            'status': 'running',
            'stage': 'initialisation'
        })

    def update(self, key, value):
        """
        Update the job status with a given key and value. The updated job status is synced to disk.
        """
        self.content[key] = value
        dump_json_to_file(self.content, self.path)

    def update_all(self, content):
        """
        Update the job status with given content (i.e., dictionary). The updated job status is synced to disk.
        """
        self.content.update(content)
        dump_json_to_file(self.content, self.path)

    def get(self, key=None):
        """
        Returns the value for a given key.
        """
        return self.content[key] if key else self.content

    def remove_all(self, keys):
        """
        Removes multiple entries (if they exists) using a list of key.
        """
        for key in keys:
            self.content.pop(key, None)
        dump_json_to_file(self.content, self.path)


def create_app():
    app = Flask(__name__)

    sys.path.insert(1, r'/processor')
    module = importlib.import_module('processor')
    with open('/processor/descriptor.json') as f:
        descriptor = json.load(f)

    @app.route('/descriptor')
    def get_descriptor():
        return jsonify(descriptor)

    @app.route('/execute', methods=['POST'])
    def execute():
        task_descriptor = request.json
        job_id = task_descriptor['job_id']

        working_path = os.path.join('/jobs_path', job_id)
        status_path = os.path.join(working_path, 'job_status.json')
        status_logger = StatusLogger(status_path)

        if module.function(task_descriptor, working_path, status_logger):
            return json.dumps({'success': True}), 200
        else:
            return json.dumps({'success': False}), 500

    return app


if __name__ == "__main__":
    create_app().run(host='0.0.0.0')
