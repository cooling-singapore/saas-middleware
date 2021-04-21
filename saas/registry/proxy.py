import json

from saas.utilities.blueprint_helpers import create_authentication, get


class EndpointProxy:
    def __init__(self, remote_address, sender):
        self.remote_address = remote_address
        self.sender = sender

    def get_node_info(self):
        url = f"http://{self.remote_address}/registry/node"

        authentication = create_authentication('GET:/registry/node', self.sender)
        content = {
            'authentication': json.dumps(authentication)
        }

        r = get(url, content)
        return r['reply']

    def get_registry_contents(self):
        url = f"http://{self.remote_address}/registry"

        authentication = create_authentication('GET:/registry', self.sender)
        content = {
            'authentication': json.dumps(authentication)
        }

        r = get(url, content)
        return r['reply']['contents']


