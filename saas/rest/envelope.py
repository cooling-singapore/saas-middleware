import os
from typing import Union, Optional

from flask import send_from_directory, jsonify
from requests import Response

from saas.helpers import validate_json
from saas.rest.exceptions import UnexpectedHTTPError, MalformedResponseError, UnsuccessfulRequestError


response_envelope_schema = {
    'type': 'object',
    'properties': {
        'status': {'type': 'string', 'enum': ['ok', 'error']}
    },
    'if': {
        'properties': {'type': {'const': 'ok'}}
    },
    'then': {
        'properties': {
            'response': {
                "anyOf": [{'type': 'object'}, {'type': 'array'}]
            }
        }
    },
    'else': {
        'properties': {
            'reason': {'type': 'string'},
            'exception_id': {'type': 'string'},
            'details': {'type': 'string'}
        },
        'required': ['reason', 'exception_id']
    },
    'required': ['status']
}


def create_ok_response(response: Union[dict, list] = None) -> (Response, int):
    """
    Creates an 'Ok' response envelope containing an optional response.
    :param response: (optional) response
    :return: response envelope
    """
    envelope = {
        'status': 'ok'
    }

    if response is not None:
        envelope['response'] = response

    return jsonify(envelope), 200


def create_ok_attachment(content_path: str) -> (Response, int):
    """
    Creates a response that streams the contents of a file.
    :param content_path: the path of the file
    :return:
    """
    head, tail = os.path.split(content_path)
    return send_from_directory(head, tail, as_attachment=True), 200


def create_error_response(reason: str, exception_id: str, details: str = None) -> (Response, int):
    """
    Creates an 'Error' response envelope containing information about the error.
    :param reason: the reason as string
    :param exception_id: the unique id of the exception
    :param details: (optional) details about the error
    :return: response envelope
    """
    envelope = {
        'status': 'error',
        'reason': reason,
        'exception_id': exception_id,
    }

    if details is not None:
        envelope['details'] = details

    return jsonify(envelope), 200


def extract_response(response: Response) -> Optional[Union[dict, list]]:
    """
    Extracts the response content in case of an 'Ok' response envelope or raises an exception in case
    of an 'Error' envelope.
    :param response: the response message
    :return: extracted response content (if any)
    :raise UnsuccessfulRequestError
    """
    # the status code should always be 200
    if response.status_code != 200:
        raise UnexpectedHTTPError({
            'response': response
        })

    # extract the JSON content and validate
    envelope = response.json()
    if not validate_json(envelope, schema=response_envelope_schema):
        raise MalformedResponseError({
            'envelope': envelope
        })

    # is the response ok or do we have an error?
    if envelope['status'] == 'ok':
        return envelope['response'] if 'response' in envelope else None

    else:
        raise UnsuccessfulRequestError({
            'reason': envelope['reason'],
            'details': envelope['details'] if 'details' in envelope else None,
            'exception_id': envelope['exception_id']
        })
