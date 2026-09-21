from abc import abstractmethod
from unittest.mock import MagicMock

import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from fence.db import DataAccessLayer, get_data_access_layer
from fence.main import get_app


class BaseTestRouter:
    @property
    @abstractmethod
    def router(self):
        raise NotImplemented()

    @pytest_asyncio.fixture(scope="function")
    async def client(self, db_session):
        """
        This fixture generates an endpoint interface to test the api

        Args:
            db_session: db db_session to interface with db
        """
        app = get_app()
        app.include_router(self.router)
        app.dependency_overrides[get_data_access_layer] = lambda: DataAccessLayer(
            db_session
        )

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as test_client:
            yield test_client

    @pytest_asyncio.fixture(scope="function")
    async def app_client_pair(self, db_session):
        """
        Bundles the app and endpoint client together

        Args:
            db_session: db db_session to interface with db
        """
        app = get_app()
        app.include_router(self.router)
        app.dependency_overrides[get_data_access_layer] = lambda: DataAccessLayer(
            db_session
        )

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as test_client:
            yield app, test_client
