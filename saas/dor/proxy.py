import json

from saas.utilities.blueprint_helpers import create_authentication, create_authorisation, post, put, get, delete
from saas.utilities.general_helpers import get_timestamp_now


class EndpointProxy:
    def __init__(self, remote_address, sender):
        self.remote_address = remote_address
        self.sender = sender

    def add_data_object(self, content_path, owner, data_type, data_format, created_by, created_t=None):
        url = f"http://{self.remote_address}/repository"
        body = {
            'type': 'data_object',
            'owner_public_key': owner.public_as_string(),
            'descriptor': {
                'data_type': data_type,
                'data_format': data_format,
                'created_t': created_t if created_t else get_timestamp_now(),
                'created_by': created_by
            }
        }

        authentication = create_authentication('POST:/repository', self.sender, body, content_path)
        content = {
            'body': json.dumps(body),
            'authentication': json.dumps(authentication)
        }

        r = post(url, content, content_path)
        return r['reply']['data_object_id'] if 'data_object_id' in r['reply'] else None

    def delete(self, obj_id, owner):
        url = f"http://{self.remote_address}/repository/{obj_id}"

        authentication = create_authentication(f"DELETE:/repository/{obj_id}", self.sender)
        authorisation = create_authorisation(f"DELETE:/repository/{obj_id}", owner)
        content = {
            'authentication': json.dumps(authentication),
            'authorisation': json.dumps(authorisation)
        }

        r = delete(url, content)
        return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None

    def get_descriptor(self, obj_id):
        url = f"http://{self.remote_address}/repository/{obj_id}/descriptor"

        authentication = create_authentication(f"GET:/repository/{obj_id}/descriptor", self.sender)
        content = {
            'authentication': json.dumps(authentication)
        }

        r = get(url, content)
        return r['reply']['descriptor'] if 'descriptor' in r['reply'] else None

    def get_content(self, obj_id, owner, download_path):
        url = f"http://{self.remote_address}/repository/{obj_id}/content"

        authentication = create_authentication(f"GET:/repository/{obj_id}/content", self.sender)
        authorisation = create_authorisation(f"GET:/repository/{obj_id}/content", owner)
        content = {
            'authentication': json.dumps(authentication),
            'authorisation': json.dumps(authorisation)
        }

        r = get(url, content, download_path)
        return r

    def get_access_permissions(self, obj_id):
        url = f"http://{self.remote_address}/repository/{obj_id}/access"

        authentication = create_authentication(f"GET:/repository/{obj_id}/access", self.sender)
        content = {
            'authentication': json.dumps(authentication)
        }

        r = get(url, content)
        return r['reply']['access'] if 'access' in r['reply'] else None

    def grant_access(self, obj_id, owner, key, permission):
        url = f"http://{self.remote_address}/repository/{obj_id}/access"

        body = {
            'public_key': key.public_as_string(),
            'permission': permission
        }
        authentication = create_authentication(f"POST:/repository/{obj_id}/access", self.sender, body)
        authorisation = create_authorisation(f"POST:/repository/{obj_id}/access", owner, body)
        content = {
            'body': json.dumps(body),
            'authentication': json.dumps(authentication),
            'authorisation': json.dumps(authorisation)
        }

        r = post(url, content)
        return r['reply']

    def revoke_access(self, obj_id, owner, key):
        url = f"http://{self.remote_address}/repository/{obj_id}/access"

        body = {
            'public_key': key.public_as_string()
        }
        authentication = create_authentication(f"DELETE:/repository/{obj_id}/access", self.sender, body)
        authorisation = create_authorisation(f"DELETE:/repository/{obj_id}/access", owner, body)
        content = {
            'body': json.dumps(body),
            'authentication': json.dumps(authentication),
            'authorisation': json.dumps(authorisation)
        }

        r = delete(url, content)
        return r['reply']

    def get_owner(self, obj_id):
        url = f"http://{self.remote_address}/repository/{obj_id}/owner"

        authentication = create_authentication(f"GET:/repository/{obj_id}/owner", self.sender)
        content = {
            'authentication': json.dumps(authentication)
        }

        r = get(url, content)
        return r['reply']

    def transfer_ownership(self, obj_id, current_owner, new_owner):
        url = f"http://{self.remote_address}/repository/{obj_id}/owner"

        body = {
            'new_owner_public_key': new_owner.public_as_string()
        }
        authentication = create_authentication(f"PUT:/repository/{obj_id}/owner", self.sender, body)
        authorisation = create_authorisation(f"PUT:/repository/{obj_id}/owner", current_owner, body)
        content = {
            'body': json.dumps(body),
            'authentication': json.dumps(authentication),
            'authorisation': json.dumps(authorisation)
        }

        r = put(url, content)
        return r['reply']

    def search_by_tags(self, key_criterion=None, value_criterion=None):
        url = f"http://{self.remote_address}/repository"
        auth_url = f"GET:/repository"

        if key_criterion:
            url = f"{url}?key_criterion={key_criterion}"
            auth_url = f"{auth_url}?key_criterion={key_criterion}"

        if value_criterion:
            url = f"{url}&value_criterion={value_criterion}"
            auth_url = f"{auth_url}&value_criterion={value_criterion}"

        authentication = create_authentication(auth_url, self.sender)
        content = {
            'authentication': json.dumps(authentication),
        }

        r = get(url, content)
        return r['reply']['objects']

    def get_tags(self, obj_id):
        url = f"http://{self.remote_address}/repository/{obj_id}/tags"

        authentication = create_authentication(f"GET:/repository/{obj_id}/tags", self.sender)
        content = {
            'authentication': json.dumps(authentication)
        }

        r = get(url, content)
        return r['reply']['tags']

    def update_tags(self, obj_id, owner, tags):
        url = f"http://{self.remote_address}/repository/{obj_id}/tags"

        # populate the tags array
        body = {'tags': []}
        for key in tags:
            value = tags[key]

            body['tags'].append({
                'key': key,
                'value': value
            })

        authentication = create_authentication(f"PUT:/repository/{obj_id}/tags", self.sender, body)
        authorisation = create_authorisation(f"PUT:/repository/{obj_id}/tags", owner, body)
        content = {
            'body': json.dumps(body),
            'authentication': json.dumps(authentication),
            'authorisation': json.dumps(authorisation)
        }

        r = put(url, content)
        return r['reply']

    def remove_tags(self, obj_id, owner, keys):
        url = f"http://{self.remote_address}/repository/{obj_id}/tags"

        body = {
            'keys': keys
        }

        authentication = create_authentication(f"DELETE:/repository/{obj_id}/tags", self.sender, body)
        authorisation = create_authorisation(f"DELETE:/repository/{obj_id}/tags", owner, body)
        content = {
            'body': json.dumps(body),
            'authentication': json.dumps(authentication),
            'authorisation': json.dumps(authorisation)
        }

        r = delete(url, content)
        return r['reply']

