import pytest

from fence.blueprints.login import DefaultOAuth2Callback
from fence.resources.openid.idp_oauth2 import Oauth2ClientBase, UpstreamRefreshToken
from fence.config import config
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
import time

@pytest.fixture(autouse=True)
def mock_arborist(mock_arborist_requests):
    mock_arborist_requests()

@patch("fence.blueprints.login.base.prepare_login_log")
def test_post_login_set_mfa(app, monkeypatch, mock_authn_user_flask_context):
    """
    Verifies the arborist is called with the mfa_policy if a given token contains the claims found in the
    configured multifactor_auth_claim_info
    """
    monkeypatch.setitem(
        config,
        "OPENID_CONNECT",
        {
            "mock_idp": {
                "multifactor_auth_claim_info": {"claim": "acr", "values": ["mfa"]}
            }
        },
    )
    callback = DefaultOAuth2Callback(
        "mock_idp", MagicMock(), username_field="username", app=app
    )

    app.arborist = MagicMock()
    token_result = {"username": "lisasimpson", "mfa": True}
    groups_from_idp = ['data_uploaders','reviewers']
    expires_at = 0
    callback.post_login(token_result=token_result,groups_from_idp=groups_from_idp,expires_at=expires_at)
    app.arborist.grant_user_policy.assert_called_with(
        username=token_result["username"], policy_id="mfa_policy"
    )

    token_result = {"username": "homersimpson", "mfa": False}
    callback.post_login(token_result=token_result,groups_from_idp=groups_from_idp,expires_at=expires_at)
    app.arborist.revoke_user_policy.assert_called_with(
        username=token_result["username"], policy_id="mfa_policy"
    )


@patch("fence.blueprints.login.base.prepare_login_log")
def test_post_login_no_mfa_enabled(app, monkeypatch, mock_authn_user_flask_context):
    """
    Verifies arborist is not called when there is no multifactor_auth_claim_info defined for the given IDP.
    """
    app.arborist = MagicMock()
    monkeypatch.setitem(
        config,
        "OPENID_CONNECT",
        {"mock_idp": {}},
    )
    with app.app_context():
        callback = DefaultOAuth2Callback(
            "mock_idp", MagicMock(), username_field="username"
        )
        token_result = {"username": "lisasimpson"}
        groups_from_idp = ['data_uploaders', 'reviewers']
        expires_at = 0
        callback.post_login(token_result=token_result,groups_from_idp=groups_from_idp,expires_at=expires_at)
        app.arborist.revoke_user_policy.assert_not_called()




