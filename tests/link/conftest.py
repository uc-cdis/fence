import pytest

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch


@pytest.fixture(scope='function')
def add_new_g_acnt_mock(db_session):
    add_new_g_acnt_mock = MagicMock()

    add_new_g_acnt_mock.return_value.id = 0
    add_new_g_acnt_mock.return_value.email = 'test'

    patcher = patch(
        'fence.blueprints.link._add_new_user_google_account',
        add_new_g_acnt_mock)
    patcher.start()

    yield add_new_g_acnt_mock

    patcher.stop()


@pytest.fixture(scope='function')
def google_auth_get_user_info_mock():
    google_auth_get_user_info_mock = MagicMock()
    patcher = patch(
        'flask.current_app.google_client.get_user_id',
        google_auth_get_user_info_mock)
    patcher.start()

    yield google_auth_get_user_info_mock

    patcher.stop()