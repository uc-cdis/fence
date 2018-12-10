"""
It is very recommended to look at the multi-tenant flow diagram before looking
at this code; otherwise it is likely for none of this to make any sense.
"""

import urllib
import urlparse

# in python3:
# urllib.parse

import fence
from fence.config import config

from tests.utils import oauth2
from tests.utils import remove_qs


def test_login(restore_config, fence_client_app, monkeypatch, oauth_client):
    """
    1. Test that the ``/oauth2/authorize`` endpoint on the client redirects to the
    ``/login/fence`` endpoint, also on the client.
    2. Test that the ``/login/fence`` client endpoint redirects to the
    ``/oauth2/authorize`` endpoint on the IDP fence
    """
    # Disable the keys refreshing since requests will not work with the client app.
    monkeypatch.setattr("authutils.token.keys.refresh_jwt_public_keys", lambda: None)

    config.update(
        {
            "OPENID_CONNECT": fence_client_app.config["OPENID_CONNECT"],
            "BASE_URL": fence_client_app.config["BASE_URL"],
            "MOCK_AUTH": fence_client_app.config["MOCK_AUTH"],
            "DEFAULT_LOGIN_URL": fence_client_app.config["DEFAULT_LOGIN_URL"],
        }
    )

    with fence_client_app.test_client() as fence_client_client:
        # 1
        data = {
            "client_id": oauth_client.client_id,
            "redirect_uri": oauth_client.url,
            "response_type": "code",
            "scope": "openid user",
            "state": fence.utils.random_str(10),
            "confirm": "yes",
        }
        response_oauth_authorize = fence_client_client.post(
            "/oauth2/authorize", data=data
        )
        assert response_oauth_authorize.status_code == 302
        assert "/login/fence" in response_oauth_authorize.location

        # 2
        redirect_url_quote = urllib.quote("/login/fence/login")
        path = "/login/fence?redirect_uri={}".format(redirect_url_quote)
        response_login_fence = fence_client_client.get(path)
        # This should be pointing at ``/oauth2/authorize`` of the IDP fence.
        assert "/oauth2/authorize" in response_login_fence.location
