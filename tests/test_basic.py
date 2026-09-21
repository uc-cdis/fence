from unittest.mock import patch, AsyncMock

import pytest

from fence.db import DataAccessLayer
from fence.main import route_aggregator
from tests.routes.conftest import BaseTestRouter


def raise_exec():
    raise Exception


@pytest.mark.asyncio
class TestConfigRouter(BaseTestRouter):
    router = route_aggregator

    @patch.object(
        DataAccessLayer, "test_connection", side_effect=Exception("Connection failed")
    )
    async def test_get_status(
        self,
        test_connection,
        client,
    ):
        result = await client.get("/_status")
        assert result.status_code == 200
