"""
Contains a number of helper functions and classes used throughout the SaaS Middleware.
"""

__author__ = "Heiko Aydt"
__email__ = "heiko.aydt@gmail.com"
__status__ = "development"

import os
import logging
import json
import tempfile
import flask

from jsonschema import validate, ValidationError
from saas.eckeypair import ECKeyPair

logger = logging.getLogger('Utilities.blueprint_helpers')


def verify_request_contents(body, specification, files, required_files=None):
    # for each element in the specification, verify the body content with the corresponding schema
    for key in specification:
        # check if the body has the required content
        if key not in body:
            return False, 400, "Missing content: '{}' required but not found.".format(key)

        # check if the content matches the schema
        content = body[key]
        schema = specification[key]
        try:
            validate(instance=content, schema=schema)

        except ValidationError:
            return False, 400, "Malformed content '{}':\ncontent={}\nschema={}".format(key, content, schema)

    # check if all required files are available
    if required_files:
        for key in required_files:
            if key not in files:
                return False, 400, "Missing content: file '{}' required but not found.".format(key)

    return True, None, None


def verify_request_authentication(url, request_content):
    # get the request body and the authentication
    body = json.loads(request_content.form['body'])
    authentication = json.loads(request_content.form['authentication'])

    # process files (if any)
    files = {}
    for k in request_content.files:
        file = flask.request.files[k]
        handle, path = tempfile.mkstemp()
        os.close(handle)
        file.save(path)
        files[k] = path

    # very the the request using the provided public key
    auth_key = ECKeyPair.from_public_key_string(authentication['public_key'])
    return auth_key.verify_authentication_token(authentication['signature'], url, body, files), body, files


def verify_request(url, request_content, body_specification={}, required_files=None):
    # verify the request signature
    verified, body, files = verify_request_authentication(url, request_content)
    if not verified:
        return False, 401, "Authentication unsuccessful.", None, None

    # verify the request contents
    verified, status_code, message = verify_request_contents(body, body_specification, files, required_files)
    if not verified:
        return False, status_code, message, None, None

    return True, None, None, body, files


def create_signed_response(node, url, status_code, reply):
    """
    Convenient function to create a response that is signed using the sending node's identity.
    :param node: the node that will send the response
    :param url: the endpoint address of the request
    :param status_code: the HTTP status code of the response
    :param reply: the reply, i.e., the content of the response (in JSON)
    :return: a signed response
    """
    signature = node.key.sign_authentication_token(url, reply)
    reply_body = {
        'reply': reply,
        'signature': signature
    }

    response = flask.jsonify(reply_body)
    response.status_code = status_code
    return response
