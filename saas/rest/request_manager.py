import functools
import os
import json
import tempfile
import traceback
from typing import Optional

import flask
import pydantic
from flask import request, Flask, g, Response

from jsonschema import validate, ValidationError
from saascore.api.sdk.exceptions import MalformedRequestError, AuthorisationFailedError, MissingResponseSchemaError, \
    MalformedResponseError
from saascore.api.sdk.helpers import verify_authorisation_token, create_error_response

from saascore.exceptions import RTIServiceNotSupportedError, DORServiceNotSupportedError, SaaSException
from saascore.helpers import validate_json
from saascore.keystore.identity import Identity
from saascore.log import Logging

logger = Logging.get('rest.request_manager')


class RequestManager:
    def __init__(self, app: Flask = None, node=None):
        self.node = node

        if app is not None and node is not None:
            self.init_app(app, node)

    def init_app(self, app: Flask, node):
        self.node = node

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

    def verify_request_body(self, body_specification: pydantic.BaseModel):
        def decorated_func(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                schema = body_specification if isinstance(body_specification, dict) else body_specification.schema()
                # for debugging purposes, get the contents of 'values' and 'form'
                values = {k: v for k, v in request.values.items()}
                form = {k: v for k, v in request.form.items()}
                logger.debug(f"request: values={values}")
                logger.debug(f"request: form={form}")

                # body will be either in request.values or request.form (not sure why).
                if 'body' in request.values:
                    body = json.loads(request.values['body'])
                elif 'body' in request.form:
                    body = json.loads(request.form['body'])
                else:
                    body = {}

                try:
                    validate(instance=body, schema=schema)

                except ValidationError:
                    raise MalformedRequestError({
                        'content': body,
                        'schema': schema
                    })

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
                        raise MalformedRequestError({
                            'expected': key,
                            'found': [*files.keys()]
                        })

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
                owner: Identity = self.node.db.get_owner(_obj_id)
                if not owner:
                    raise AuthorisationFailedError({
                        'obj_id': _obj_id,
                        'owner': None
                    })

                # verify the the request using the owner public key
                form = request.form.to_dict()
                authorisation = json.loads(form['authorisation'])
                if not verify_authorisation_token(owner, authorisation['signature'], url, body):
                    raise AuthorisationFailedError({
                        'obj_id': _obj_id,
                        'owner': owner.serialise(),
                        'authorisation': authorisation,
                        'url': url,
                        'body': body
                    })

                return func(*args, **kwargs)
            return wrapper
        return decorated_func

    def verify_authorisation_by_user(self, obj_id: str):
        def decorated_func(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # determine url and body
                url = f'{request.method}:{request.path}'
                _obj_id = kwargs[obj_id]
                body = json.loads(request.values['body']) if 'body' in request.values else None

                # is the object access restricted?
                obj_meta = self.node.db.get_object_by_id(_obj_id)
                if obj_meta['access_restricted']:
                    # get the authorisation information
                    form = request.form.to_dict()
                    authorisation = json.loads(form['authorisation'])

                    # iterate over all identities and figure out if the authorisation public key is among
                    # the identities that have access
                    for user_iid in obj_meta['access']:
                        user = self.node.db.get_identity(user_iid)
                        user_public_key = user.s_public_key_as_string() if user else ''
                        auth_public_key = authorisation['public_key']
                        if user_public_key == auth_public_key:
                            # verify the the request using the owner public key
                            if verify_authorisation_token(user, authorisation['signature'], url, body):
                                return func(*args, **kwargs)
                            else:
                                raise AuthorisationFailedError({
                                    'obj_id': _obj_id,
                                    'user': user.serialise(),
                                    'authorisation': authorisation,
                                    'url': url,
                                    'body': body
                                })

                    # if we have reached here then either no user has been granted access or the authorisation
                    # public key doesn't match. let's try the owner as last instance.
                    owner: Identity = self.node.db.get_owner(_obj_id)
                    if not owner:
                        raise AuthorisationFailedError({
                            'obj_id': _obj_id,
                            'owner': None
                        })

                    # verify the the request using the owner public key
                    if verify_authorisation_token(owner, authorisation['signature'], url, body):
                        return func(*args, **kwargs)
                    else:
                        raise AuthorisationFailedError({
                            'obj_id': _obj_id,
                            'owner': owner.serialise(),
                            'authorisation': authorisation,
                            'url': url,
                            'body': body
                        })

                return func(*args, **kwargs)
            return wrapper
        return decorated_func

    def require_dor(self):
        def decorated_func(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                if self.node.dor is None:
                    raise DORServiceNotSupportedError()

                return func(*args, **kwargs)
            return wrapper
        return decorated_func

    def require_rti(self):
        def decorated_func(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                if self.node.rti is None:
                    raise RTIServiceNotSupportedError()

                return func(*args, **kwargs)

            return wrapper

        return decorated_func

    def handle_request(self, response_schema: Optional[pydantic.BaseModel] = None):
        def decorated_func(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    # call the function that handles this endpoint
                    response: (Response, int) = func(*args, **kwargs)

                    # if we have a response content, check if it is valid
                    if response[0].headers['Content-Type'] == 'application/json':
                        content = response[0].json
                        if response[0].status_code == 200 and content != {}:
                            # do we have a schema?
                            if response_schema is None:
                                raise MissingResponseSchemaError({
                                    'rule': f"{request.method}:{request.url_rule}",
                                    'content': content
                                })

                            # is the response content valid?
                            schema = response_schema if isinstance(response_schema, dict) else response_schema.schema()
                            if not validate_json(content, schema):
                                raise MalformedResponseError({
                                    'rule': f"{request.method}:{request.url_rule}",
                                    'content': content,
                                    'schema': schema
                                })

                    return response

                except SaaSException as e:
                    trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
                    logger.error(f"[endpoint_error:{e.id}] {e.reason}\n{e.details}\n{trace}")

                    return create_error_response(
                        reason=e.reason,
                        exception_id=e.id
                    )

            return wrapper

        return decorated_func


request_manager = RequestManager()
