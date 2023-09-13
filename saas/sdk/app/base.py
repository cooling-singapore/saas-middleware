from __future__ import annotations

import abc
import os
import threading
import time
from threading import Lock
from typing import List, Union, Dict, Optional, Tuple

import uvicorn
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from threading import Thread

from pydantic import BaseModel
from starlette.responses import JSONResponse

from saas.core.exceptions import SaaSRuntimeException
from saas.core.logging import Logging
from saas.rest.exceptions import UnsupportedRESTMethod
from saas.rest.schemas import EndpointDefinition, Token
from saas.sdk.app.auth import UserAuth, UserDB, User
from saas.sdk.base import SDKContext, connect
from saas.sdk.dot import DataObjectType

logger = Logging.get('saas.sdk.app')

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class TokenData(BaseModel):
    username: Union[str, None] = None


class UpdateUserParameters(BaseModel):
    password: Optional[Tuple[str, str]]
    name: Optional[str]


class UserProfile(BaseModel):
    login: str
    name: str
    disabled: bool


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, UserAuth.secret_key, algorithms=[UserAuth.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token_data = TokenData(username=username)

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # try to get the user
    user = UserDB.get_user(login=token_data.username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


class Application(abc.ABC):
    def __init__(self, address: (str, int), node_address: (str, int), endpoint_prefix: (str, str),
                 wd_path: str, title: str, version: str, description: str, context_expiry: int = 30) -> None:

        self._mutex = Lock()
        self._address = address
        self._node_address = node_address
        self._endpoint_prefix = endpoint_prefix
        self._title = title
        self._version = version
        self._description = description

        self._wd_path = wd_path
        os.makedirs(os.path.join(self._wd_path), exist_ok=True)

        self._mutex = Lock()
        self._api = FastAPI(
            openapi_url=f"{self._endpoint_prefix[0]}/openapi.json",
            docs_url=f"{self._endpoint_prefix[0]}/docs"
        )
        self._thread = None

        self._context: Dict[str, SDKContext] = {}
        self._dots: Dict[str, DataObjectType] = {}

        self._invalidate_thread = threading.Thread(target=self._invalidate_contexts,
                                                   args=(context_expiry,),
                                                   daemon=True)
        self._invalidate_thread.start()

    def _register(self, endpoint: EndpointDefinition) -> None:
        route = f"{endpoint.prefix[0]}/{endpoint.prefix[1]}/{endpoint.rule}" \
            if endpoint.prefix[1] else f"{endpoint.prefix[0]}/{endpoint.rule}"

        logger.info(f"REST app is mapping {endpoint.method}:{route} to {endpoint.function}")
        if endpoint.method == 'POST':
            self._api.post(route,
                           response_model=endpoint.response_model,
                           dependencies=endpoint.dependencies,
                           description=endpoint.function.__doc__)(endpoint.function)
        elif endpoint.method == 'GET':
            self._api.get(route,
                          response_model=endpoint.response_model,
                          dependencies=endpoint.dependencies,
                          description=endpoint.function.__doc__)(endpoint.function)
        elif endpoint.method == 'PUT':
            self._api.put(route,
                          response_model=endpoint.response_model,
                          dependencies=endpoint.dependencies,
                          description=endpoint.function.__doc__)(endpoint.function)
        elif endpoint.method == 'DELETE':
            self._api.delete(route,
                             response_model=endpoint.response_model,
                             dependencies=endpoint.dependencies,
                             description=endpoint.function.__doc__)(endpoint.function)
        else:
            raise UnsupportedRESTMethod(endpoint.method, route)

    def _invalidate_contexts(self, expiry: int) -> None:
        logger.debug(f"[context_invalidator] invalidating contexts after {expiry} minutes.")
        while True:
            time.sleep(30)
            with self._mutex:
                for key in list(self._context.keys()):
                    context = self._context[key]
                    if context.age > expiry:
                        logger.debug(f"[context_invalidator] context expired: {context.authority}")
                        self._context.pop(key)

    def _get_context(self, user: User) -> SDKContext:
        with self._mutex:
            if user.login not in self._context:
                logger.debug(f"[context_invalidator] context created: {user.login}")
                self._context[user.login] = connect(self._node_address, user.keystore)
            return self._context[user.login]

    async def _close(self) -> None:
        logger.info("REST app is shutting down.")

    def add_dot(self, dot: DataObjectType) -> None:
        with self._mutex:
            self._dots[dot.name()] = dot

    def supported_dots(self) -> List[str]:
        with self._mutex:
            return list(self._dots.keys())

    @property
    def address(self) -> (str, int):
        return self._address

    @property
    def endpoint_prefix(self) -> (str, str):
        return self._endpoint_prefix

    @abc.abstractmethod
    def endpoints(self) -> List[EndpointDefinition]:
        pass

    def startup(self) -> None:
        if self._thread is None:
            self._api.on_event("shutdown")(self._close)

            # collect endpoints
            endpoints = self.endpoints()
            endpoints.append(EndpointDefinition('POST', (self._endpoint_prefix[0], ''), 'token',
                                                UserAuth.login_for_access_token, Token, None))

            endpoints.append(EndpointDefinition('GET', (self._endpoint_prefix[0], ''), 'user/profile',
                                                self.get_user, UserProfile, None))

            endpoints.append(EndpointDefinition('PUT', (self._endpoint_prefix[0], ''), 'user/profile',
                                                self.update_user, UserProfile, None))

            # add endpoints
            for endpoint in endpoints:
                self._register(endpoint)

            # update the openapi schema
            self._api.openapi_schema = get_openapi(
                title=self._title,
                version=self._version,
                description=self._description,
                routes=self._api.routes
            )

            @self._api.exception_handler(SaaSRuntimeException)
            async def exception_handler(_: Request, exception: SaaSRuntimeException):
                return JSONResponse(
                    status_code=500,
                    content={
                        'reason': exception.reason,
                        'id': exception.id,
                        'details': exception.details
                    }
                )

            # setup CORS
            self._api.add_middleware(
                CORSMiddleware,
                allow_origins=['*'],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )

            logger.info("REST service starting up...")
            self._thread = Thread(target=uvicorn.run, args=(self._api,),
                                  kwargs={"host": self._address[0], "port": self._address[1], "log_level": "info"},
                                  daemon=True)

            self._thread.start()
            # await asyncio.sleep(0.1)

        else:
            logger.warning("REST service asked to start up but thread already exists! Ignoring...")

    def shutdown(self) -> None:
        if self._thread is None:
            logger.warning("REST service asked to shut down but thread does not exist! Ignoring...")

        else:
            logger.info("REST service shutting down...")
            # there is no way to terminate a thread...
            # self._thread.terminate()

    def get_user(self, user: User = Depends(get_current_active_user)) -> UserProfile:
        """
        Returns the user profile.
        """
        return UserProfile(login=user.login, name=user.name, disabled=user.disabled)

    def update_user(self, p: UpdateUserParameters, user: User = Depends(get_current_active_user)) -> UserProfile:
        """
        Updates a user information (name and/or password) and returns the user profile.
        """
        user = UserDB.update_user(user.login, False, password=p.password, user_display_name=p.name)
        return UserProfile(login=user.login, name=user.name, disabled=user.disabled)
