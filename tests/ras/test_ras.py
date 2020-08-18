import time
import unittest
import mock
import jwt

from cdislogging import get_logger

from fence.models import User, UpstreamRefreshToken, GA4GHVisaV1
from fence.resources.openid.ras_oauth2 import RASOauth2Client as RASClient
from fence.config import config
import tests.utils

logger = get_logger(__name__, log_level="debug")


@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_userinfo")
@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_access_token")
@mock.patch(
    "fence.resources.openid.ras_oauth2.RASOauth2Client.get_value_from_discovery_doc"
)
def test_update_visa_token(
    mock_discovery,
    mock_get_token,
    mock_userinfo,
    config,
    db_session,
    rsa_private_key,
    kid,
):

    mock_discovery.return_value = "https://ras/token_endpoint"

    new_token = "refresh12345abcdefg"
    token_response = {
        "access_token": "abcdef12345",
        "id_token": "id12345abcdef",
        "refresh_token": new_token,
    }
    mock_get_token.return_value = token_response

    userinfo_response = {
        "sub": "abcd-asdj-sajpiasj12iojd-asnoin",
        "name": "",
        "preferred_username": "someuser@era.com",
        "UID": "",
        "UserID": "admin_user",
        "email": "",
    }
    mock_userinfo.return_value = userinfo_response

    test_user = User(username="admin_user", id="5678", is_admin=True)
    db_session.add(test_user)
    db_session.commit()
    print(test_user.id)

    refresh_token = "abcde1234567kposjdas"
    expires = int(time.time()) + 1000

    db_session.add(
        UpstreamRefreshToken(
            refresh_token=refresh_token, user_id=test_user.id, expires=expires,
        )
    )
    db_session.commit()

    oidc = config.get("OPENID_CONNECT", {})
    ras_client = RASClient(
        oidc["ras"], HTTP_PROXY=config.get("HTTP_PROXY"), logger=logger,
    )

    claims = {
        "iss": "https://stsstg.nih.gov",
        "sub": "abcde12345aspdij",
        "iat": int(time.time()),
        "exp": int(time.time()) + 1000,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": "jtiajoidasndokmasdl",
        "txn": "sapidjspa.asipidja",
        "name": "",
        "ga4gh_visa_v1": {
            "type": "https://ras/visa/v1",
            "asserted": int(time.time()),
            "value": "https://nig/passport/dbgap",
            "source": "https://ncbi/gap",
        },
    }
    headers = {"kid": kid}
    visa = jwt.encode(
        claims, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")
    userinfo_response["ga4gh_passport_v1"] = [visa]

    ras_client.update_user_visas(test_user)

    visa = db_session.query(GA4GHVisaV1).first()
    assert visa.ga4gh_visa
