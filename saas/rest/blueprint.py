import traceback

from flask import Blueprint, request
from requests import Response

from saas.exceptions import SaaSException
from saas.logging import Logging
from saas.rest.envelope import create_error_response
from saas.rest.exceptions import EndpointNotSupportedError

logger = Logging.get('rest.blueprint')


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
            return record['function'](**args)

        except SaaSException as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            logger.error(f"[endpoint_error:{e.id}] {e.reason}\n{e.details}\n{trace}")

            return create_error_response(
                reason=e.reason,
                exception_id=e.id
            )
