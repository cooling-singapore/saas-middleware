import json
import time
import traceback
from typing import Union, Optional

import requests

from saas.core.exceptions import SaaSRuntimeException
from saas.core.helpers import hash_string_object, hash_json_object, hash_bytes_object
from saas.core.keystore import Keystore
from saas.rest.exceptions import UnexpectedHTTPError, UnsuccessfulRequestError, UnexpectedContentType, \
    UnsuccessfulConnectionError


def extract_response(response: requests.Response) -> Optional[Union[dict, list]]:
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
        try:
            content = response.json()
        except Exception as e:
            trace = ''.join(traceback.format_exception(None, e, e.__traceback__))
            raise SaaSRuntimeException("Unexpected error", details={
                'exception': e,
                'trace': trace
            })

        raise UnsuccessfulRequestError(
            content['reason'], content['id'], content['details'] if 'details' in content else None
        )

    else:
        raise UnexpectedHTTPError({
            'response': response
        })


def generate_authorisation_token(authority: Keystore, url: str, body: dict = None, precision: int = 5) -> str:
    slot = int(time.time() / precision)

    # logger.info("sign_authorisation_token\tH(url)={}".format(hash_json_object(url).hex()))
    token = hash_string_object(url).hex()

    if body:
        # logger.info("sign_authorisation_token\tH(body)={}".format(hash_json_object(body).hex()))
        token += hash_json_object(body).hex()

    # logger.info("sign_authorisation_token\tH(bytes(slot))={}".format(hash_bytes_object(bytes(slot)).hex()))
    token += hash_bytes_object(bytes(slot)).hex()

    # logger.info("sign_authorisation_token\tH(self.public_as_string())={}".format(hash_string_object(self.public_as_string()).hex()))
    token += hash_string_object(authority.signing_key.public_as_string()).hex()

    token = hash_string_object(token)
    # logger.info("sign_authorisation_token\ttoken={}".format(token.hex()))

    return authority.sign(token)


def _make_headers(authority: Keystore, url: str, body: Union[dict, list] = None) -> Optional[dict]:
    return {
        'saasauth-iid': authority.identity.id,
        'saasauth-signature': generate_authorisation_token(authority, url, body)
    }


class EndpointProxy:
    def __init__(self, endpoint_prefix: str, remote_address: (str, int)) -> None:
        self._endpoint_prefix = endpoint_prefix
        self._remote_address = remote_address

    @property
    def remote_address(self) -> (str, int):
        return self._remote_address

    def get(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None, download_path: str = None,
            with_authorisation_by: Keystore = None) -> Optional[Union[dict, list]]:

        url = self._make_url(endpoint, parameters)
        headers = _make_headers(with_authorisation_by, f"GET:{url}", body) if with_authorisation_by else {}

        try:
            if download_path:
                with requests.get(url, headers=headers, data=body, stream=True) as response:
                    header = {k.lower(): v for k, v in response.headers.items()}
                    if header['content-type'] == 'application/json':
                        return extract_response(response)

                    elif response.headers['content-type'] == 'application/octet-stream':
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
                response = requests.get(url, headers=headers, json=body)
                return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def put(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None, attachment_path: str = None,
            with_authorisation_by: Keystore = None) -> Union[dict, list]:

        url = self._make_url(endpoint, parameters)
        headers = _make_headers(with_authorisation_by, f"PUT:{url}", body) if with_authorisation_by else {}

        try:
            if attachment_path:
                response = requests.post(url,
                                         data={'body': json.dumps(body)},
                                         files={'attachment': open(attachment_path, 'rb')})
                return extract_response(response)

            else:
                response = requests.put(url, headers=headers, json=body)
                return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def post(self, endpoint: str, body: Union[dict, list, str] = None, parameters: dict = None,
             attachment_path: str = None, with_authorisation_by: Keystore = None) -> Union[dict, list]:

        url = self._make_url(endpoint, parameters)
        headers = _make_headers(with_authorisation_by, f"POST:{url}", body) if with_authorisation_by else {}

        try:
            if attachment_path:
                with open(attachment_path, 'rb') as f:
                    response = requests.post(url,
                                             data={'body': json.dumps(body)},
                                             files={'attachment': f})
                    return extract_response(response)

            else:
                response = requests.post(url, headers=headers, json=body)
                return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def delete(self, endpoint: str, body: Union[dict, list] = None, parameters: dict = None,
               with_authorisation_by: Keystore = None) -> Union[dict, list]:

        url = self._make_url(endpoint, parameters)
        headers = _make_headers(with_authorisation_by, f"DELETE:{url}", body) if with_authorisation_by else {}

        try:
            response = requests.delete(url, headers=headers, json=body)
            return extract_response(response)

        except requests.exceptions.ConnectionError:
            raise UnsuccessfulConnectionError(url)

    def _make_url(self, endpoint: str, parameters: dict = None) -> str:
        url = f"http://{self._remote_address[0]}:{self._remote_address[1]}{self._endpoint_prefix}{endpoint}"
        if parameters:
            for i in range(len(parameters)):
                url += '?' if i == 0 else '&'
                url += parameters[i][0] + '=' + parameters[i][1]
        return url
