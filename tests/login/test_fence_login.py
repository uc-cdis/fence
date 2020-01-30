from addict import Dict
from authutils.oauth2.client import OAuthClient
from collections import OrderedDict
import pytest

import fence
from fence.config import config
from fence.jwt.keys import Keypair


@pytest.fixture(scope="function")
def config_idp_in_client(
    app, db_session, kid_2, rsa_private_key_2, rsa_public_key_2, restore_config
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
            },
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
