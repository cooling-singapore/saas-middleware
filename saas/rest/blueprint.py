import os
import traceback
from typing import Union, Optional

from flask import Blueprint, request, send_from_directory, jsonify
from requests import Response

from saas.exceptions import SaaSException
from saas.helpers import validate_json
from saas.logging import Logging
from saas.rest.exceptions import EndpointNotSupportedError, UnexpectedHTTPError, MalformedResponseError, \
    UnsuccessfulRequestError, MissingResponseSchemaError

logger = Logging.get('rest.blueprint')

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


class SaaSBlueprint:
    def __init__(self, name: str, import_name: str, endpoint_prefix: str):
        self._name = name
        self._import_name = import_name
        self._endpoint_prefix = endpoint_prefix
        self._rules = {}

    def add_rule(self, rule: str, function, methods: list[str], response_schema: dict = None):
        """
        Adds an endpoint rule.
        :param rule: the rule, i.e., the path of the endpoint
        :param function: the function that handles this endpoint
        :param methods: the HTTP methods supported for this endpoint
        :param response_schema: (optional) the JSON schema for the response content (if any)
        :return:
        """
        for method in methods:
            key = f"{method}:{self._endpoint_prefix}/{rule}" if rule else f"{method}:{self._endpoint_prefix}"
            if key in self._rules:
                logger.warning(f"overwriting REST endpoint rule '{key}'")

            self._rules[key] = {
                'rule': rule,
                'function': function,
                'methods': methods,
                'schema': response_schema
            }

    def generate_blueprint(self):
        """
        Generates a blueprint based on the previously added rules (if any).
        :return:
        """
        blueprint = Blueprint(self._name, self._import_name, url_prefix=self._endpoint_prefix)

        for v in self._rules.values():
            blueprint.add_url_rule(
                v['rule'], self._handle_request.__name__, self._handle_request, methods=v['methods']
            )

        return blueprint

    def _handle_request(self, **args) -> (Response, int):
        try:
            # do we have this rule registered?
            rule = f"{request.method}:{request.url_rule}"
            if rule not in self._rules:
                raise EndpointNotSupportedError({
                    'rule': rule,
                    'supported': [*self._rules.keys()],
                    'args': args
                })

            # get the rule and call the function that handles this endpoint
            record = self._rules[rule]
            response: (Response, int) = record['function'](**args)

            # if we have a response content, check if it is valid
            if response[0].headers['Content-Type'] == 'application/json':
                envelope = response[0].json
                if envelope['status'] == 'ok' and 'response' in envelope:
                    # do we have a schema?
                    if record['schema'] is None:
                        raise MissingResponseSchemaError({
                            'rule': rule,
                            'response': envelope['response']
                        })

                    # is the response content valid?
                    if not validate_json(envelope['response'], record['schema']):
                        raise MalformedResponseError({
                            'rule': rule,
                            'response': envelope['response'],
                            'schema': record['schema']
                        })

            return response

        except SaaSException as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            logger.error(f"[endpoint_error:{e.id}] {e.reason}\n{e.details}\n{trace}")

            return create_error_response(
                reason=e.reason,
                exception_id=e.id
            )
