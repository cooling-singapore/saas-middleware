import json
import requests

from saas.utilities.blueprint_helpers import create_authentication, create_authorisation


class EndpointProxy:
    def __init__(self, endpoint_prefix, remote_address, sender):
        self._endpoint_prefix = endpoint_prefix
        self._remote_address = remote_address
        self._sender = sender

    def url(self, endpoint, parameters=None):
        return f"http://{self._remote_address[0]}:{self._remote_address[1]}{self._auth_url(endpoint, parameters)}"

    def _auth_url(self, endpoint, parameters=None):
        url = f"{self._endpoint_prefix}{endpoint}"

        if parameters:
            for i in range(len(parameters)):
                url += '?' if i == 0 else '&'
                url += parameters[i][0] + '=' + parameters[i][1]

        return url

    def get(self, endpoint, body=None, parameters=None, download_path=None,
            with_authentication=True, with_authorisation_by=None):

        content = self._make_content(endpoint, 'GET', parameters=parameters, body=body,
                                     with_authentication=with_authentication,
                                     with_authorisation_by=with_authorisation_by)

        url = self.url(endpoint, parameters)
        if download_path:
            with requests.get(url, data=content, stream=True) as r:
                if r.status_code == 401:
                    return 401

                with open(download_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)

                return r.status_code

        else:
            return requests.get(url, data=content).json()

    def put(self, endpoint, body=None, parameters=None, attachment=None,
            with_authentication=True, with_authorisation_by=None):

        content = self._make_content(endpoint, 'PUT', parameters=parameters, body=body, attachment=attachment,
                                     with_authentication=with_authentication,
                                     with_authorisation_by=with_authorisation_by)

        url = self.url(endpoint, parameters)
        if attachment:
            with open(attachment, 'rb') as f:
                return requests.put(url, data=content, files={'attachment': f.read()}).json()
        else:
            return requests.put(url, data=content).json()

    def post(self, endpoint, body=None, parameters=None, attachment=None,
             with_authentication=True, with_authorisation_by=None):

        content = self._make_content(endpoint, 'POST', parameters=parameters, body=body, attachment=attachment,
                                     with_authentication=with_authentication,
                                     with_authorisation_by=with_authorisation_by)

        url = self.url(endpoint, parameters)
        if attachment:
            with open(attachment, 'rb') as f:
                return requests.post(url, data=content, files={'attachment': f.read()}).json()
        else:
            return requests.post(url, data=content).json()

    def delete(self, endpoint, body=None, parameters=None,
               with_authentication=True, with_authorisation_by=None):

        content = self._make_content(endpoint, 'DELETE', parameters=parameters, body=body,
                                     with_authentication=with_authentication,
                                     with_authorisation_by=with_authorisation_by)

        url = self.url(endpoint, parameters)
        return requests.delete(url, data=content).json()

    def _make_content(self, endpoint, action, parameters=None, body=None, attachment=None,
                      with_authentication=True, with_authorisation_by=None):
        content = {}

        if body:
            content['body'] = json.dumps(body)

        if with_authentication:
            authentication = create_authentication(f"{action}:{self._auth_url(endpoint, parameters)}",
                                                   self._sender, body=body, attachment=attachment)
            content['authentication'] = json.dumps(authentication)

        if with_authorisation_by:
            authorisation = create_authorisation(f"{action}:{self._auth_url(endpoint, parameters)}",
                                                 with_authorisation_by, body=body)
            content['authorisation'] = json.dumps(authorisation)

        return content



