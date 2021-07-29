import json
import requests


class EndpointProxy:
    def __init__(self, endpoint_prefix, remote_address):
        self._endpoint_prefix = endpoint_prefix
        self._remote_address = remote_address

    def url(self, endpoint, parameters=None):
        return f"http://{self._remote_address[0]}:{self._remote_address[1]}{self._auth_url(endpoint, parameters)}"

    def _auth_url(self, endpoint, parameters=None):
        url = f"{self._endpoint_prefix}{endpoint}"

        if parameters:
            for i in range(len(parameters)):
                url += '?' if i == 0 else '&'
                url += parameters[i][0] + '=' + parameters[i][1]

        return url

    def get(self, endpoint, body=None, parameters=None, download_path=None, with_authorisation_by=None):

        content = self._make_content(endpoint, 'GET', parameters=parameters, body=body,
                                     with_authorisation_by=with_authorisation_by)

        url = self.url(endpoint, parameters)
        if download_path:
            with requests.get(url, data=content, stream=True) as response:
                if response.status_code == 401:
                    return response.status_code, response.json()

                with open(download_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                return response.status_code, response.json

        else:
            response = requests.get(url, data=content)
            return response.status_code, response.json()

    def put(self, endpoint, body=None, parameters=None, attachment=None, with_authorisation_by=None):

        content = self._make_content(endpoint, 'PUT', parameters=parameters, body=body,
                                     with_authorisation_by=with_authorisation_by)

        url = self.url(endpoint, parameters)
        if attachment:
            with open(attachment, 'rb') as f:
                response = requests.put(url, data=content, files={'attachment': f.read()})
                return response.status_code, response.json()
        else:
            response = requests.put(url, data=content)
            return response.status_code, response.json()

    def post(self, endpoint, body=None, parameters=None, attachment=None, with_authorisation_by=None):

        content = self._make_content(endpoint, 'POST', parameters=parameters, body=body,
                                     with_authorisation_by=with_authorisation_by)

        url = self.url(endpoint, parameters)
        if attachment:
            with open(attachment, 'rb') as f:
                response = requests.post(url, data=content, files={'attachment': f.read()})
                return response.status_code, response.json()
        else:
            response = requests.post(url, data=content)
            return response.status_code, response.json()

    def delete(self, endpoint, body=None, parameters=None, with_authorisation_by=None):

        content = self._make_content(endpoint, 'DELETE', parameters=parameters, body=body,
                                     with_authorisation_by=with_authorisation_by)

        url = self.url(endpoint, parameters)
        response = requests.delete(url, data=content)
        return response.status_code, response.json()

    def _make_content(self, endpoint, action, parameters=None, body=None, with_authorisation_by=None):
        content = {}

        if body:
            content['body'] = json.dumps(body)

        if with_authorisation_by:
            url = f"{action}:{self._auth_url(endpoint, parameters)}"
            authorisation = {
                    'public_key': with_authorisation_by.public_as_string(),
                    'signature': with_authorisation_by.sign_authorisation_token(url, body)
            }

            content['authorisation'] = json.dumps(authorisation)

        return content



