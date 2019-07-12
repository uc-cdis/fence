import pytest

from unittest.mock import MagicMock, patch


@pytest.fixture(scope="function")
def add_new_g_acnt_mock(db_session):
    mock = MagicMock()

    mock.return_value.id = 0
    mock.return_value.email = "test"

    patcher = patch("fence.blueprints.link.add_new_user_google_account", mock)
    patcher.start()

    yield mock

    patcher.stop()


@pytest.fixture(scope="function")
def google_auth_get_user_info_mock():
    mock = MagicMock()
    patcher = patch("flask.current_app.google_client.get_user_id", mock)
    patcher.start()

    yield mock

    patcher.stop()


@pytest.fixture(scope="function")
def add_google_email_to_proxy_group_mock():
    mock = MagicMock()
    patcher = patch("fence.blueprints.link._add_google_email_to_proxy_group", mock)
    patcher.start()

    yield mock

    patcher.stop()
