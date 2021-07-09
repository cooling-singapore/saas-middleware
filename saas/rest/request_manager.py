import functools
import os
import logging
import json
import tempfile
import flask
from flask import request, Flask, g

from jsonschema import validate, ValidationError

logger = logging.getLogger('rest.request_manager')


class RequestError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message


class AuthenticationFailedError(RequestError):
    def __init__(self, code, message):
        super().__init__(code, message)


class AuthorisationFailedError(RequestError):
    def __init__(self, code, message):
        super().__init__(code, message)


class MalformedRequestError(RequestError):
    def __init__(self, code, message):
        super().__init__(code, message)


class RequestManager:
    def __init__(self, app: Flask = None, node=None):
        self.node = node

        if app is not None and node is not None:
            self.init_app(app, node)

    def init_app(self, app: Flask, node):
        self.node = node
        self._set_error_handler_callbacks(app)

    def _set_error_handler_callbacks(self, app: Flask):
        @app.errorhandler(RequestError)
        def handle_failed_request(e: RequestError):
            """
            Handles any failed request such as authentication errors

            :param e: RequestError object
            :return: Response
            """
            logger.error(e)

            response = flask.jsonify(e.message)
            response.status_code = e.code
            return response

    def _set_request_variable(self, name: str, value):
        """
        Stores request variables (e.g. body or files) to global context to be retrieved by decorators.

        :param name: Name of variable
        :param value: Value of variable
        """
        if '_request_var' not in g:
            g._request_var = {}
        g._request_var[name] = value

    def get_request_variable(self, name: str):
        values = g.get('_request_var', {})
        return values.get(name, None)

    def verify_request_body(self, body_specification):
        def decorated_func(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                body = json.loads(request.values['body'])

                try:
                    validate(instance=body, schema=body_specification)

                except ValidationError:
                    raise MalformedRequestError(400, f"Malformed content:\ncontent={json.dumps(body, indent=3)}\n"
                                                     f"schema={json.dumps(body_specification, indent=3)}")

                self._set_request_variable('body', body)
                return func(*args, **kwargs)
            return wrapper
        return decorated_func

    def verify_request_files(self, required_files):
        def decorated_func(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # create a dictionary of the files sent with the request
                files = {}
                for k in request.files:
                    file = flask.request.files[k]
                    handle, path = tempfile.mkstemp()
                    os.close(handle)
                    file.save(path)
                    files[k] = path

                # check if all required files are available
                for key in required_files:
                    if key not in files:
                        raise MalformedRequestError(400, f"Missing content: file '{key}' required but not found.")

                self._set_request_variable('files', files)
                return func(*args, **kwargs)
            return wrapper
        return decorated_func

    def verify_authorisation_by_owner(self, obj_id: str):
        def decorated_func(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # determine url and body
                url = f'{request.method}:{request.path}'
                _obj_id = kwargs[obj_id]
                body = json.loads(request.values['body']) if 'body' in request.values else None

                # get the owner identity
                owner = self.node.db.get_owner(_obj_id)
                if not owner:
                    raise AuthorisationFailedError(404, f"Owner for data object '{_obj_id}' not found.")

                # verify the the request using the owner public key
                form = request.form.to_dict()
                authorisation = json.loads(form['authorisation'])
                if not owner.signing_public_key().verify_authorisation_token(authorisation['signature'], url, body):
                    raise AuthorisationFailedError(401, "Authorisation failed.")

                return func(*args, **kwargs)
            return wrapper
        return decorated_func


request_manager = RequestManager()
