import functools
import os
import json
import tempfile
import time
import traceback

import flask
from flask import request, Flask, g, Response

from jsonschema import validate, ValidationError

from saas.cryptography.hashing import hash_string_object, hash_json_object, hash_bytes_object
from saas.exceptions import RTIServiceNotSupportedError, DORServiceNotSupportedError, SaaSException
from saas.helpers import validate_json
from saas.keystore.identity import Identity
from saas.keystore.keystore import Keystore
from saas.logging import Logging
from saas.rest.blueprint import create_error_response
from saas.rest.exceptions import MalformedRequestError, AuthorisationFailedError, EndpointNotSupportedError, \
    MissingResponseSchemaError, MalformedResponseError

logger = Logging.get('rest.request_manager')


def sign_authorisation_token(authority: Keystore,
                             url: str, body: dict = None, precision: int = 5) -> str:
    slot = int(time.time() / precision)

    # logger.info("sign_authorisation_token\tH(url)={}".format(hash_json_object(url).hex()))
    token = hash_string_object(url).hex()

    if body:
        # logger.info("sign_authorisation_token\tH(body)={}".format(hash_json_object(body).hex()))
        token += hash_json_object(body).hex()

    # logger.info("sign_authorisation_token\tH(bytes(slot))={}".format(hash_bytes_object(bytes(slot)).hex()))
    token += hash_bytes_object(bytes(slot)).hex()

    # logger.info("sign_authorisation_token\tH(self.public_as_string())={}".format(hash_string_object(self.public_as_string()).hex()))
    token += hash_string_object(authority.signing_key().public_as_string()).hex()

    token = hash_string_object(token)
    # logger.info("sign_authorisation_token\ttoken={}".format(token.hex()))

    return authority.sign(token)


def verify_authorisation_token(identity: Identity, signature: str,
                               url: str, body: dict = None, precision: int = 5) -> bool:
    # determine time slots (we allow for some variation before and after)
    ref = int(time.time() / precision)
    slots = [ref - 1, ref, ref + 1]

    # generate the token for each time slot and check if for one the signature is valid.
    for slot in slots:
        # logger.info("verify_authorisation_token\tH(url)={}".format(hash_json_object(url).hex()))
        token = hash_string_object(url).hex()

        if body:
            # logger.info("verify_authorisation_token\tH(body)={}".format(hash_json_object(body).hex()))
            token += hash_json_object(body).hex()

        # logger.info("verify_authorisation_token\tH(bytes(slot))={}".format(hash_bytes_object(bytes(slot)).hex()))
        token += hash_bytes_object(bytes(slot)).hex()

        # logger.info("verify_authorisation_token\tH(self.public_as_string())={}".format(
        #     hash_string_object(self.public_as_string()).hex()))
        token += hash_string_object(identity.s_public_key_as_string()).hex()

        token = hash_string_object(token)
        # logger.info("verify_authorisation_token\ttoken={}".format(token.hex()))

        if identity.verify(token, signature):
            return True

    # no valid signature for any of the eligible timeslots
    return False


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

    def verify_request_body(self, body_specification):
        def decorated_func(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
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
                    validate(instance=body, schema=body_specification)

                except ValidationError:
                    raise MalformedRequestError({
                        'content': body,
                        'schema': body_specification
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

    def handle_request(self, schema: dict):
        def decorated_func(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    # call the function that handles this endpoint
                    response: (Response, int) = func(*args, **kwargs)

                    # if we have a response content, check if it is valid
                    if response[0].headers['Content-Type'] == 'application/json':
                        envelope = response[0].json
                        if envelope['status'] == 'ok' and 'response' in envelope:
                            # do we have a schema?
                            if schema is None:
                                raise MissingResponseSchemaError({
                                    'rule': f"{request.method}:{request.url_rule}",
                                    'response': envelope['response']
                                })

                            # is the response content valid?
                            if not validate_json(envelope['response'], schema):
                                raise MalformedResponseError({
                                    'rule': f"{request.method}:{request.url_rule}",
                                    'response': envelope['response'],
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
