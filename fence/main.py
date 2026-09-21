from contextlib import asynccontextmanager
from importlib.metadata import version
import logging
from typing import AsyncIterable

import fastapi
from fastapi import FastAPI, HTTPException, APIRouter

from fence import config
from fence.routes.basic import basic_router
from fence.db import get_data_access_layer, DataAccessLayer

route_aggregator = APIRouter()

route_definitions = [
    (basic_router, "", ["Basic"]),
]

for router, prefix, tags in route_definitions:
    route_aggregator.include_router(router, prefix=prefix, tags=tags)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await check_db_connection()

    yield


async def check_db_connection():
    """
    Simple check to ensure we can talk to db
    """
    try:
        logging.debug(
            "Startup database connection test initiating. Attempting a simple query..."
        )
        dals: AsyncIterable[DataAccessLayer] = get_data_access_layer()
        async for data_access_layer in dals:
            outcome = await data_access_layer.test_connection()
            logging.debug("Startup database connection test PASSED.")
    except Exception as exc:
        logging.exception(
            "Startup database connection test FAILED. Unable to connect to the configured database."
        )
        logging.debug(exc)
        raise


def get_app() -> FastAPI:
    """
    Return the web framework app object after adding routes

    Returns:
        FastAPI: FastAPI app object
    """

    fastapi_app = FastAPI(
        title="Gen3 Fence Service",
        version=version("fence"),
        # debug=config.DEBUG,
        # root_path=config.URL_PREFIX,
        lifespan=lifespan,
    )
    fastapi_app.include_router(route_aggregator)

    # MISSING A WHOLE BUNCH OF THINGS

    return fastapi_app
