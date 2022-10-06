import uvicorn

from threading import Thread
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from starlette.responses import JSONResponse

from saas.core.exceptions import SaaSRuntimeException
from saas.core.logging import Logging
from saas._meta import __title__, __version__, __description__
from saas.rest.exceptions import UnsupportedRESTMethod
from saas.rest.schemas import EndpointDefinition

logger = Logging.get('rest.service')


class RESTApp:
    def __init__(self, origins: list[str] = None) -> None:
        self.api = FastAPI()
        self.api.on_event("shutdown")(self.close)

        @self.api.exception_handler(SaaSRuntimeException)
        async def saas_exception_handler(_: Request, exception: SaaSRuntimeException):
            return JSONResponse(
                status_code=500,
                content={
                    'reason': exception.reason,
                    'id': exception.id,
                    'details': exception.details
                }
            )

        # setup CORS
        self.api.add_middleware(
            CORSMiddleware,
            allow_origins=origins if origins else ['*'],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    def register(self, endpoint: EndpointDefinition) -> None:
        route = f"{endpoint.prefix}/{endpoint.rule}"
        logger.info(f"REST app is mapping {endpoint.method}:{route} to {endpoint.function}")
        if endpoint.method == 'POST':
            self.api.post(route,
                          response_model=endpoint.response_model,
                          dependencies=endpoint.dependencies,
                          description=endpoint.function.__doc__)(endpoint.function)
        elif endpoint.method == 'GET':
            self.api.get(route,
                         response_model=endpoint.response_model,
                         dependencies=endpoint.dependencies,
                         description=endpoint.function.__doc__)(endpoint.function)
        elif endpoint.method == 'PUT':
            self.api.put(route,
                         response_model=endpoint.response_model,
                         dependencies=endpoint.dependencies,
                         description=endpoint.function.__doc__)(endpoint.function)
        elif endpoint.method == 'DELETE':
            self.api.delete(route,
                            response_model=endpoint.response_model,
                            dependencies=endpoint.dependencies,
                            description=endpoint.function.__doc__)(endpoint.function)
        else:
            raise UnsupportedRESTMethod(endpoint.method, route)

    async def close(self) -> None:
        logger.info(f"REST app is shutting down.")


class RESTService:
    def __init__(self, node, host: str, port: int) -> None:
        self._node = node
        self._host = host
        self._port = port
        self._app = RESTApp()
        self._thread = None

    def address(self) -> (str, int):
        return self._host, self._port

    def add(self, endpoints: list[EndpointDefinition]) -> None:
        for endpoint in endpoints:
            if endpoint.dependencies:
                endpoint.dependencies = [Depends(d(self._node)) for d in endpoint.dependencies]

            self._app.register(endpoint)

        # update the openapi schema
        self._app.api.openapi_schema = get_openapi(
            title=__title__,
            version=__version__,
            description=__description__,
            routes=self._app.api.routes
        )

    def start_service(self) -> None:
        if self._thread is None:
            logger.info(f"REST service starting up...")
            self._thread = Thread(target=uvicorn.run, args=(self._app.api,),
                                  kwargs={"host": self._host, "port": self._port, "log_level": "info"},
                                  daemon=True)

            self._thread.start()
            # await asyncio.sleep(0.1)

        else:
            logger.warning(f"REST service asked to start up but thread already exists! Ignoring...")

    def stop_service(self) -> None:
        if self._thread is None:
            logger.warning(f"REST service asked to shut down but thread does not exist! Ignoring...")

        else:
            logger.info(f"REST service shutting down...")
            # there is no way to terminate a thread...
            # self._thread.terminate()
