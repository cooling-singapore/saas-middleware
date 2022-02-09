from flask import Blueprint
from saascore.log import Logging

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
                v['rule'], v['function'].__name__, v['function'], methods=v['methods']
            )

        return blueprint
