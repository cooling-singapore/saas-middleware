import json
from typing import Union, Optional

import requests

from saas.keystore.keystore import Keystore
from saas.rest.blueprint import extract_response
from saas.rest.exceptions import UnexpectedContentType, UnsuccessfulRequestError, UnsuccessfulConnectionError
from saas.rest.request_manager import sign_authorisation_token


class EndpointProxy:
    def __init__(self, endpoint_prefix: str, remote_address: (str, int)) -> None:
        self._endpoint_prefix = endpoint_prefix
        self._remote_address = remote_address

    def get(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None, download_path: str = None,
            with_authorisation_by: Keystore = None) -> Optional[Union[dict, list]]:

        content = self._make_content(endpoint, 'GET', parameters=parameters, body=body,
                                     with_authorisation_by=with_authorisation_by)

        url = self._url(endpoint, parameters)
        try:
            if download_path:
                with requests.get(url, data=content, stream=True) as response:
                    header = {k: v for k, v in response.headers.items()}
                    if header['Content-Type'] == 'application/json':
                        return extract_response(response)

                    elif response.headers['Content-Type'] == 'application/octet-stream':
                        content = response.iter_content(chunk_size=8192)
                        with open(download_path, 'wb') as f:
                            for chunk in content:
                                f.write(chunk)
                        return header

                    else:
                        raise UnexpectedContentType({
                            'header': header
                        })

            else:
                response = requests.get(url, data=content)
                return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def put(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None, attachment_path: str = None,
            with_authorisation_by: Keystore = None) -> Union[dict, list]:

        content = self._make_content(endpoint, 'PUT', parameters=parameters, body=body,
                                     with_authorisation_by=with_authorisation_by)

        url = self._url(endpoint, parameters)
        try:
            if attachment_path:
                with open(attachment_path, 'rb') as f:
                    response = requests.put(url, data=content, files={'attachment': f.read()})
                    return extract_response(response)

            else:
                response = requests.put(url, data=content)
                return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def post(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None, attachment_path: str = None,
             with_authorisation_by: Keystore = None) -> Union[dict, list]:

        content = self._make_content(endpoint, 'POST',
                                     parameters=parameters,
                                     body=body,
                                     with_authorisation_by=with_authorisation_by)

        url = self._url(endpoint, parameters)
        try:
            if attachment_path:
                with open(attachment_path, 'rb') as f:
                    response = requests.post(url, data=content, files={'attachment': f.read()})
                    return extract_response(response)

            else:
                response = requests.post(url, data=content)
                return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def delete(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None,
               with_authorisation_by: Keystore = None) -> Union[dict, list]:

        content = self._make_content(endpoint, 'DELETE',
                                     parameters=parameters,
                                     body=body,
                                     with_authorisation_by=with_authorisation_by)

        url = self._url(endpoint, parameters)
        try:
            response = requests.delete(url, data=content)
            return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def _auth_url(self, endpoint: str, parameters: dict = None) -> str:
        url = f"{self._endpoint_prefix}{endpoint}"

        if parameters:
            for i in range(len(parameters)):
                url += '?' if i == 0 else '&'
                url += parameters[i][0] + '=' + parameters[i][1]

        return url

    def _url(self, endpoint: str, parameters: dict = None) -> str:
        return f"http://{self._remote_address[0]}:{self._remote_address[1]}{self._auth_url(endpoint, parameters)}"

    def _make_content(self, endpoint: str, action: str, parameters: dict = None, body: Union[dict, list] = None,
                      with_authorisation_by: Keystore = None):
        content = {}

        if body:
            content['body'] = json.dumps(body)

        if with_authorisation_by:
            url = f"{action}:{self._auth_url(endpoint, parameters)}"
            authorisation = {
                    'public_key': with_authorisation_by.signing_key().public_as_string(),
                    'signature': sign_authorisation_token(with_authorisation_by, url, body)
            }

            content['authorisation'] = json.dumps(authorisation)

        return content
