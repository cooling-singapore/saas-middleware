import json
import os
import subprocess
import traceback

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException


def create_app():
    app = Flask(__name__)

    @app.route('/execute', methods=['POST'])
    def execute():
        data = request.json
        job_id = data['job_id']
        working_directory = os.path.join('/jobs_path', job_id)

        subprocess.run(['python', '/processor.py', working_directory], check=True)
        return jsonify({'success': True}), 200

    @app.errorhandler(Exception)
    def handle_exception(e):

        if isinstance(e, HTTPException):
            return e

        tb = traceback.format_exc()
        print(tb)
        return json.dumps({'success': False, 'stack_trace': tb}), 500

    return app


if __name__ == "__main__":
    create_app().run(host='0.0.0.0')
