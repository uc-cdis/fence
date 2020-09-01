import time
import mock
import jwt

from cdislogging import get_logger

from fence.models import User, UpstreamRefreshToken, GA4GHVisaV1
from fence.resources.openid.ras_oauth2 import RASOauth2Client as RASClient
from fence.config import config
import tests.utils

logger = get_logger(__name__, log_level="debug")


def add_test_user(db_session):
    test_user = User(username="admin_user", id="5678", is_admin=True)
    db_session.add(test_user)
    db_session.commit()
    return test_user


def add_visa_manually(db_session, user, rsa_private_key, kid):

    headers = {"kid": kid}

    decoded_visa = {
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

    encoded_visa = jwt.encode(
        decoded_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")

    visa = GA4GHVisaV1(
        user=user,
        source=decoded_visa["ga4gh_visa_v1"]["source"],
        type=decoded_visa["ga4gh_visa_v1"]["type"],
        asserted=int(decoded_visa["ga4gh_visa_v1"]["asserted"]),
        expires=int(decoded_visa["exp"]),
        ga4gh_visa=encoded_visa,
    )

    db_session.add(visa)
    db_session.commit()


def add_refresh_token(db_session, user):
    refresh_token = "abcde1234567kposjdas"
    expires = int(time.time()) + 1000

    db_session.add(
        UpstreamRefreshToken(
            refresh_token=refresh_token,
            user_id=user.id,
            expires=expires,
        )
    )
    db_session.commit()


def test_store_refresh_token(db_session):
    """
    Test to check if store_refresh_token replaces the existing token with a new one in the db
    """

    test_user = add_test_user(db_session)
    add_refresh_token(db_session, test_user)
    initial_query = db_session.query(UpstreamRefreshToken).first()
    assert initial_query.refresh_token

    new_refresh_token = "newtoken1234567"
    new_expire = 50000

    oidc = config.get("OPENID_CONNECT", {})
    ras_client = RASClient(
        oidc["ras"],
        HTTP_PROXY=config.get("HTTP_PROXY"),
        logger=logger,
    )

    ras_client.store_refresh_token(test_user, new_refresh_token, new_expire)

    final_query = db_session.query(UpstreamRefreshToken).first()
    assert final_query.refresh_token == new_refresh_token
    assert final_query.expires == new_expire


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
    kid_2,
):
    """
    Test to check visa table is updated when getting new visa
    """

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

    test_user = add_test_user(db_session)
    add_visa_manually(db_session, test_user, rsa_private_key, kid)
    add_refresh_token(db_session, test_user)

    visa_query = db_session.query(GA4GHVisaV1).filter_by(user=test_user).first()
    initial_visa = visa_query.ga4gh_visa
    assert initial_visa

    oidc = config.get("OPENID_CONNECT", {})
    ras_client = RASClient(
        oidc["ras"],
        HTTP_PROXY=config.get("HTTP_PROXY"),
        logger=logger,
    )

    new_visa = {
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

    headers = {"kid": kid_2}

    encoded_visa = jwt.encode(
        new_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")

    userinfo_response["ga4gh_passport_v1"] = [encoded_visa]
    mock_userinfo.return_value = userinfo_response

    ras_client.update_user_visas(test_user)

    query_visa = db_session.query(GA4GHVisaV1).first()
    assert query_visa.ga4gh_visa
    assert query_visa.ga4gh_visa == encoded_visa


@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_userinfo")
@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_access_token")
@mock.patch(
    "fence.resources.openid.ras_oauth2.RASOauth2Client.get_value_from_discovery_doc"
)
def test_update_visa_empty_visa_returned(
    mock_discovery,
    mock_get_token,
    mock_userinfo,
    config,
    db_session,
    rsa_private_key,
    kid,
    kid_2,
):
    """
    Test to check if the db is emptied if the ras userinfo sends back an empty visa
    """

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
    userinfo_response["ga4gh_passport_v1"] = []

    mock_userinfo.return_value = userinfo_response

    test_user = add_test_user(db_session)
    add_visa_manually(db_session, test_user, rsa_private_key, kid)
    add_refresh_token(db_session, test_user)

    visa_query = db_session.query(GA4GHVisaV1).filter_by(user=test_user).first()
    initial_visa = visa_query.ga4gh_visa
    assert initial_visa

    oidc = config.get("OPENID_CONNECT", {})
    ras_client = RASClient(
        oidc["ras"],
        HTTP_PROXY=config.get("HTTP_PROXY"),
        logger=logger,
    )

    ras_client.update_user_visas(test_user)

    query_visa = db_session.query(GA4GHVisaV1).first()
    assert query_visa == None


@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_userinfo")
@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_access_token")
@mock.patch(
    "fence.resources.openid.ras_oauth2.RASOauth2Client.get_value_from_discovery_doc"
)
def test_update_visa_token_with_invalid_visa(
    mock_discovery,
    mock_get_token,
    mock_userinfo,
    config,
    db_session,
    rsa_private_key,
    kid,
    kid_2,
):
    """
    Test to check the following case:
    Received visa: [good1, bad2, good3]
    Processed/stored visa: [good1, good3]
    """

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

    test_user = add_test_user(db_session)
    add_visa_manually(db_session, test_user, rsa_private_key, kid)
    add_refresh_token(db_session, test_user)

    visa_query = db_session.query(GA4GHVisaV1).filter_by(user=test_user).first()
    initial_visa = visa_query.ga4gh_visa
    assert initial_visa

    oidc = config.get("OPENID_CONNECT", {})
    ras_client = RASClient(
        oidc["ras"],
        HTTP_PROXY=config.get("HTTP_PROXY"),
        logger=logger,
    )

    new_visa = {
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

    headers = {"kid": kid_2}

    encoded_visa = jwt.encode(
        new_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")

    userinfo_response["ga4gh_passport_v1"] = [encoded_visa, [], encoded_visa]
    mock_userinfo.return_value = userinfo_response

    ras_client.update_user_visas(test_user)

    query_visas = db_session.query(GA4GHVisaV1).filter_by(user=test_user).all()
    assert len(query_visas) == 2
    for query_visa in query_visas:
        assert query_visa.ga4gh_visa
        assert query_visa.ga4gh_visa == encoded_visa
