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
import requests

from jsonschema import validate, ValidationError
from saas.eckeypair import ECKeyPair
from saas.utilities.general_helpers import get_timestamp_now, all_in_dict


logger = logging.getLogger('Utilities.blueprint_helpers')


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


def verify_request_authentication(url, request_content):
    """
    Convenient function that verifies the authentication for a request.
    :param url: the endpoint address of the request
    :param request_content: the request object (containing 'forms' and 'files')
    :return:
    """
    # process files (if any)
    files = {}
    for k in request_content.files:
        file = flask.request.files[k]
        handle, path = tempfile.mkstemp()
        os.close(handle)
        file.save(path)
        files[k] = path

    # check if authentication is available
    form = request_content.form.to_dict()
    if 'authentication' not in form:
        raise AuthenticationFailedError(401, "Missing authentication information. Authentication failed.")

    # verify the the request using the provided public key
    authentication = json.loads(form['authentication'])
    auth_key = ECKeyPair.from_public_key_string(authentication['public_key'])
    body = json.loads(form['body']) if 'body' in form else None

    if not auth_key.verify_authentication_token(authentication['signature'], url, body, files):
        raise AuthenticationFailedError(401, "Mismatching signature. Authentication failed.")

    return body, files


def verify_request_body(body, body_specification):
    """
    Convenient function to verify that the body of a request is adhering to its specification (i.e., JSON schema)
    :param body: the body of request (i.e., a JSON object)
    :param body_specification: the specification of the body (i.e., a JSON schema)
    :return: None
    """
    try:
        validate(instance=body, schema=body_specification)

    except ValidationError:
        raise MalformedRequestError(400, f"Malformed content:\ncontent={json.dumps(body, indent=3)}\n"
                                         f"schema={json.dumps(body_specification, indent=3)}")


def verify_request_files(files, required):
    """
    Convenient function that checks if the files of a request contain the required list of files.
    :param files: a list of files that came with a request
    :param required: list of required files (by filename)
    :return:
    """
    # check if all required files are available
    for key in required:
        if key not in files:
            raise MalformedRequestError(400, f"Missing content: file '{key}' required but not found.")


def verify_authorisation_by_owner(request_content, obj_id, node, url, body=None):
    """
    Convenient function to verify that the authorisation for accessing a data object is valid and created by the
    owner of the data object.
    :param request_content: the request object (containing 'forms' and 'files')
    :param obj_id: the data object id
    :param node: the node that is handling the request
    :param url: the endpoint address of the request
    :param body: the body (if any) that came with the request
    :return: the owner identity of the data object (if verification successful)
    """
    owner = node.dor.get_owner(obj_id)
    if not owner:
        raise AuthorisationFailedError(404, f"Owner for data object '{obj_id}' not found.")

    # check if authentication is available
    form = request_content.form.to_dict()
    if 'authentication' not in form:
        raise AuthenticationFailedError(401, "Authentication missing.")

    # verify the the request using the owner public key
    authorisation = json.loads(form['authorisation'])
    if not owner.verify_authorisation_token(authorisation['signature'], url, body):
        raise AuthorisationFailedError(401, "Authorisation failed.")

    return owner


def verify_authorisation_by_user(request_content, obj_id, node, url, body=None):
    """
    Convenient function to verify that the authorisation for accessing a data object is valid and created by a
    permitted user of the data object.
    :param request_content: the request object (containing 'forms' and 'files')
    :param obj_id: the data object id
    :param node: the node that is handling the request
    :param url: the endpoint address of the request
    :param body: the body (if any) that came with the request
    :return: the user identity of the data object (if verification successful)
    """
    # check if authorisation is available
    form = request_content.form.to_dict()
    if 'authorisation' not in form:
        raise AuthenticationFailedError(401, "Authorisation missing.")

    # get the public key of the user
    authorisation = json.loads(form['authorisation'])
    user = ECKeyPair.from_public_key_string(authorisation['public_key'])

    # does the user have access rights?
    if not node.dor.has_access(obj_id, user):
        raise AuthorisationFailedError(401, f"User '{user.iid}' has no permission to access data object '{obj_id}'.")

    # verify the the request using the user public key
    if not user.verify_authorisation_token(authorisation['signature'], url, body):
        raise AuthorisationFailedError(401, "Authorisation failed.")

    return user


def create_signed_response(node, url, status_code, reply=None):
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
        'signature': signature
    }
    if reply:
        reply_body['reply'] = reply

    response = flask.jsonify(reply_body)
    response.status_code = status_code
    return response


def create_authentication(url, auth_key, body=None, attachment_path=None):
    return {
        'public_key': auth_key.public_as_string(),
        'signature':
            auth_key.sign_authentication_token(url, body=body, files=[attachment_path]) if attachment_path else
            auth_key.sign_authentication_token(url, body=body)
    }


def create_authorisation(url, auth_key, body=None):
    return {
        'public_key': auth_key.public_as_string(),
        'signature': auth_key.sign_authorisation_token(url, body)
    }


def request_dor_add(address, sender, owner, content_path, task_descriptor, output_name, data_type, data_format='json', creator='unknown'):
    recipe = {
        'task_descriptor': task_descriptor,
        'output_name': output_name
    }

    url = f"http://{address[0]}:{address[1]}/repository"
    body = {
        'type': 'data_object',
        'owner_public_key': owner.public_as_string(),
        'descriptor': {
            'data_type': data_type,
            'data_format': data_format,
            'created_t': get_timestamp_now(),
            'created_by': creator,
            'recipe': recipe
        }
    }

    authentication = create_authentication('POST:/repository', sender, body, content_path)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    with open(content_path, 'rb') as f:
        r = requests.post(url, data=content, files={'attachment': f.read()}).json()
        return r['reply']['data_object_id'] if 'data_object_id' in r['reply'] else None


def request_rti_submit_task(address, sender, owner, proc_id, input_descriptor):
    input_descriptor_array = []
    for item in input_descriptor.items():
        input_descriptor_array.append(item[1])

    url = f"http://{address[0]}:{address[1]}/processor/{proc_id}/jobs"
    body = {
        'type': 'task',
        'descriptor': {
            'processor_id': proc_id,
            'input': input_descriptor_array,
            'output': {
                'owner_public_key': owner.public_as_string()
            }
        }
    }

    authentication = create_authentication(f"POST:/processor/{proc_id}/jobs", sender, body)
    content = {
        'body': json.dumps(body),
        'authentication': json.dumps(authentication)
    }

    r = requests.post(url, data=content).json()
    return r['reply']['job_id'] if 'job_id' in r['reply'] else None


def request_rti_job_status(address, sender, proc_id, job_id):
    url = f"http://{address[0]}:{address[1]}/processor/{proc_id}/jobs/{job_id}"
    authentication = create_authentication(f"GET:/processor/{proc_id}/jobs/{job_id}", sender)
    content = {
        'authentication': json.dumps(authentication)
    }

    r = requests.get(url, data=content).json()
    return (r['reply']['job_descriptor'], r['reply']['status']) \
        if all_in_dict(['job_descriptor', 'status'], r['reply']) else None
