import os
from typing import Union, Optional

from flask import Blueprint, send_from_directory, jsonify
from requests import Response

from saas.helpers import validate_json
from saas.logging import Logging
from saas.rest.exceptions import UnexpectedHTTPError, MalformedResponseError, UnsuccessfulRequestError

logger = Logging.get('rest.blueprint')

error_response_schema = {
    'type': 'object',
    'properties': {
        'reason': {'type': 'string'},
        'exception_id': {'type': 'string'},
        'details': {'type': 'string'}
    },
    'required': ['reason', 'exception_id']
}


def create_ok_response(content: Union[dict, list] = None) -> (Response, int):
    """
    Creates an 'Ok' response envelope containing an optional response.
    :param content: (optional) response content
    :return: response
    """
    return jsonify(content if content else {}), 200


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
    content = {
        'status': 'error',
        'reason': reason,
        'exception_id': exception_id,
    }

    if details is not None:
        content['details'] = details

    return jsonify(content), 500


def extract_response(response: Response) -> Optional[Union[dict, list]]:
    """
    Extracts the response content in case of an 'Ok' response envelope or raises an exception in case
    of an 'Error' envelope.
    :param response: the response message
    :return: extracted response content (if any)
    :raise UnsuccessfulRequestError
    """

    if response.status_code == 200:
        return response.json()

    elif response.status_code == 500:
        # validate the JSON content
        content = response.json()
        if not validate_json(content, schema=error_response_schema):
            raise MalformedResponseError({
                'content': content
            })

        raise UnsuccessfulRequestError({
            'reason': content['reason'],
            'details': content['details'] if 'details' in content else None,
            'exception_id': content['exception_id']
        })

    else:
        raise UnexpectedHTTPError({
            'response': response
        })


class SaaSBlueprint:
    def __init__(self, name: str, import_name: str, endpoint_prefix: str):
        self._name = name
        self._import_name = import_name
        self._endpoint_prefix = endpoint_prefix
        self._rules = {}

    def add_rule(self, rule: str, function, methods: list[str]):
        """
        Adds an endpoint rule.
        :param rule: the rule, i.e., the path of the endpoint
        :param function: the function that handles this endpoint
        :param methods: the HTTP methods supported for this endpoint
        :return:
        """
        for method in methods:
            key = f"{method}:{self._endpoint_prefix}/{rule}" if rule else f"{method}:{self._endpoint_prefix}"
            if key in self._rules:
                logger.warning(f"overwriting REST endpoint rule '{key}'")

            self._rules[key] = {
                'rule': rule,
                'function': function,
                'methods': methods
            }

    def generate_blueprint(self):
        """
        Generates a blueprint based on the previously added rules (if any).
        :return:
        """
        blueprint = Blueprint(self._name, self._import_name, url_prefix=self._endpoint_prefix)

        for v in self._rules.values():
            blueprint.add_url_rule(
                v['rule'], v['function'].__name__, v['function'], methods=v['methods']
            )

        return blueprint
