from collections import OrderedDict

from addict import Dict
from authutils.oauth2.client import OAuthClient
import mock
import pytest
import requests

import fence
from fence.config import config
from fence.jwt.keys import Keypair


@pytest.fixture(scope="function")
def config_idp_in_client(
    app,
    db_session,
    kid_2,
    rsa_private_key_2,
    rsa_public_key_2,
    restore_config,
):
    """
    Set info about this fence's (client fence's) IDP in config.
    Reset when done.
    """

    saved_keypairs = app.keypairs
    keypair = Keypair(
        kid=kid_2, public_key=rsa_public_key_2, private_key=rsa_private_key_2
    )
    app.keypairs = [keypair]

    saved_jwtpks = app.jwt_public_keys
    app.jwt_public_keys["/"] = OrderedDict([(kid_2, rsa_public_key_2)])

    saved_db_Session = app.db.Session
    app.db.Session = lambda: db_session

    config.update(
        {
            "BASE_URL": "/",
            "MOCK_AUTH": False,
            "DEFAULT_LOGIN_URL": "/login/fence",
            "OPENID_CONNECT": {
                "fence": {
                    "client_id": "other_fence_client_id",
                    "client_secret": "other_fence_client_secret",
                    "api_base_url": "http://other-fence",
                    "authorize_url": "http://other-fence/oauth2/authorize",
                }
            }
        }
    )
    app.fence_client = OAuthClient(**config["OPENID_CONNECT"]["fence"])

    yield Dict(
        client_id=config["OPENID_CONNECT"]["fence"]["client_id"],
        client_secret=config["OPENID_CONNECT"]["fence"]["client_secret"],
    )

    app.keypairs = saved_keypairs
    app.jwt_public_keys = saved_jwtpks
    app.db.Session = saved_db_Session


def test_redirect_oauth2_authorize(app, client, config_idp_in_client):
    """
    Test that the ``/oauth2/authorize`` endpoint on the client fence redirects to the
    ``/login/fence`` endpoint, also on the client fence, 
    in the multi-tenant setup case.
    """
    r = client.post("/oauth2/authorize")
    assert r.status_code == 302
    assert "/login/fence" in r.location
    assert config["BASE_URL"] in r.location


def test_redirect_login_fence(app, client, config_idp_in_client):
    """
    Test that the ``/login/fence`` endpoint on the client fence redirects to the
    ``/oauth2/authorize`` endpoint on the IDP fence, in the multi-tenant setup case.
    """
    path = "/login/fence"
    r = client.get(path)
    assert r.status_code == 302
    assert "/oauth2/authorize" in r.location
    assert config["OPENID_CONNECT"]["fence"]["api_base_url"] in r.location


def test_downstream_idps_no_idp(app, client):
    """
    If we don't include the config here, then the client doesn't have any fence IDP, so
    this endpoint should return 404.
    """
    response = client.get("/login/downstream-idps")
    assert response.status_code == 404


def test_downstream_idps_no_shibboleth(app, client, config_idp_in_client):
    """
    If we include the config pointing to a fence IDP but the IDP fence doesn't have
    shibboleth, that request will 404, and this request should also return 404.
    """

    def mock_get_404(*args, **kwargs):
        mocked_response = mock.MagicMock(requests.Response)
        mocked_response.status_code = 404
        return mocked_response

    with mock.patch("fence.blueprints.login.fence_login.requests.get", mock_get_404):
        response = client.get("/login/downstream-idps")
        assert response.status_code == 404


def test_downstream_idps(app, client, config_idp_in_client):
    """
    Test that if we mock the request to `/Shibboleth.sso/DiscoFeed` on the IDP fence,
    this client fence will correctly return the same response from
    `/login-downstream-idps`.
    """
    entityID = "urn:mace:incommon:uchicago.edu"

    def mock_get(*args, **kwargs):
        mocked_response = mock.MagicMock(requests.Response)
        mocked_response.status_code = 200
        mocked_response.json.return_value = [{
            "entityID": entityID,
            "DisplayNames": [
                {
                    "value": "University of Chicago",
                    "lang": "en"
                    }
                ],
            "Descriptions": [
                {
                    "value": "The University of Chicago Web Single Sign-On servce",
                    "lang": "en"
                    }
                ],
            "PrivacyStatementURLs": [
                {
                    "value": "https://its.uchicago.edu/acceptable-use-policy/",
                    "lang": "en"
                    }
                ],
            "Logos": [
                {
                    "value": "https://shibboleth2.uchicago.edu/idp/shib_img/idplogo.png",
                    "height": "83",
                    "width": "350",
                    "lang": "en"
                }
            ]
        }]
        return mocked_response

    with mock.patch("fence.blueprints.login.fence_login.requests.get", mock_get):
        response = client.get("/login/downstream-idps")
        assert len(response.json) == 1
        assert [entity for entity in response.json if entity["entityID"] == entityID]
        assert response.status_code == 200
