import asyncio
import flask
import httpx
import time
import mock
import jwt

from cdislogging import get_logger

from fence.config import config
from fence.models import User, UpstreamRefreshToken, GA4GHVisaV1
from fence.resources.openid.ras_oauth2 import RASOauth2Client as RASClient
from fence.config import config

from tests.dbgap_sync.conftest import add_visa_manually
from fence.job.visa_update_cronjob import Visa_Token_Update
import tests.utils

logger = get_logger(__name__, log_level="debug")


def add_test_user(db_session, username="admin_user", id="5678", is_admin=True):
    test_user = User(username=username, id=id, is_admin=is_admin)
    # id is part of primary key
    check_user_exists = db_session.query(User).filter_by(id=id).first()
    if not check_user_exists:
        db_session.add(test_user)
        db_session.commit()
    return test_user


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
    rsa_public_key,
    kid,
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
            "type": "https://ras.nih.gov/visas/v1",
            "asserted": int(time.time()),
            "value": "https://nig/passport/dbgap",
            "source": "https://ncbi/gap",
        },
    }

    headers = {"kid": kid}

    encoded_visa = jwt.encode(
        new_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    new_passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": "abcde12345aspdij",
        "iat": int(time.time()),
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": int(time.time()) + 1000,
        "ga4gh_passport_v1": [encoded_visa],
    }

    encoded_passport = jwt.encode(
        new_passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    ).decode("utf-8")

    userinfo_response["passport_jwt_v11"] = encoded_passport
    mock_userinfo.return_value = userinfo_response

    pkey_cache = {
        "https://stsstg.nih.gov": {
            kid: rsa_public_key,
        }
    }
    ras_client.update_user_visas(test_user, pkey_cache=pkey_cache)

    query_visa = db_session.query(GA4GHVisaV1).first()
    assert query_visa.ga4gh_visa
    assert query_visa.ga4gh_visa == encoded_visa


@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_userinfo")
@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_access_token")
@mock.patch(
    "fence.resources.openid.ras_oauth2.RASOauth2Client.get_value_from_discovery_doc"
)
def test_update_visa_empty_passport_returned(
    mock_discovery,
    mock_get_token,
    mock_userinfo,
    config,
    db_session,
    rsa_private_key,
    rsa_public_key,
    kid,
):
    """
    Test to handle empty passport sent from RAS
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
        "passport_jwt_v11": "",
    }
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

    pkey_cache = {
        "https://stsstg.nih.gov": {
            kid: rsa_public_key,
        }
    }
    ras_client.update_user_visas(test_user, pkey_cache=pkey_cache)

    query_visa = db_session.query(GA4GHVisaV1).first()
    assert query_visa == None


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

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    new_passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": "abcde12345aspdij",
        "iat": int(time.time()),
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": int(time.time()) + 1000,
        "ga4gh_passport_v1": [],
    }
    encoded_passport = jwt.encode(
        new_passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    ).decode("utf-8")

    userinfo_response["passport_jwt_v11"] = encoded_passport
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

    ras_client.update_user_visas(test_user, pkey_cache={})

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
    rsa_public_key,
    kid,
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
            "type": "https://ras.nih.gov/visas/v1",
            "asserted": int(time.time()),
            "value": "https://nig/passport/dbgap",
            "source": "https://ncbi/gap",
        },
    }

    headers = {"kid": kid}

    encoded_visa = jwt.encode(
        new_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    new_passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": "abcde12345aspdij",
        "iat": int(time.time()),
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": int(time.time()) + 1000,
    }
    new_passport["ga4gh_passport_v1"] = [encoded_visa, [], encoded_visa]

    encoded_passport = jwt.encode(
        new_passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    ).decode("utf-8")
    userinfo_response["passport_jwt_v11"] = encoded_passport

    mock_userinfo.return_value = userinfo_response

    pkey_cache = {
        "https://stsstg.nih.gov": {
            kid: rsa_public_key,
        }
    }
    ras_client.update_user_visas(test_user, pkey_cache=pkey_cache)

    query_visas = db_session.query(GA4GHVisaV1).filter_by(user=test_user).all()
    assert len(query_visas) == 2
    for query_visa in query_visas:
        assert query_visa.ga4gh_visa
        assert query_visa.ga4gh_visa == encoded_visa


@mock.patch("httpx.get")
@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_userinfo")
@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_access_token")
@mock.patch(
    "fence.resources.openid.ras_oauth2.RASOauth2Client.get_value_from_discovery_doc"
)
def test_update_visa_fetch_pkey(
    mock_discovery,
    mock_get_token,
    mock_userinfo,
    mock_httpx_get,
    db_session,
    rsa_private_key,
    kid,
):
    """
    Test that when the RAS client's pkey cache is empty, the client's
    update_user_visas can fetch and serialize the visa issuer's public keys and
    validate a visa using the correct key.
    """
    mock_discovery.return_value = "https://ras/token_endpoint"
    mock_get_token.return_value = {
        "access_token": "abcdef12345",
        "id_token": "id12345abcdef",
        "refresh_token": "refresh12345abcdefg",
    }
    # New visa that will be returned by userinfo
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
            "type": "https://ras.nih.gov/visas/v1",
            "asserted": int(time.time()),
            "value": "https://nig/passport/dbgap",
            "source": "https://ncbi/gap",
        },
    }
    headers = {"kid": kid}
    encoded_visa = jwt.encode(
        new_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    new_passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": "abcde12345aspdij",
        "iat": int(time.time()),
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": int(time.time()) + 1000,
        "ga4gh_passport_v1": [encoded_visa],
    }

    encoded_passport = jwt.encode(
        new_passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    ).decode("utf-8")

    mock_userinfo.return_value = {
        "passport_jwt_v11": encoded_passport,
    }

    # Mock the call to the jwks endpoint so it returns the test app's keypairs,
    # one of which is rsa_private_key (and its corresponding public key), which
    # we just used to sign new_visa.
    keys = [keypair.public_key_to_jwk() for keypair in flask.current_app.keypairs]
    mock_httpx_get.return_value = httpx.Response(200, json={"keys": keys})

    oidc = config.get("OPENID_CONNECT", {})
    ras_client = RASClient(
        oidc["ras"],
        HTTP_PROXY=config.get("HTTP_PROXY"),
        logger=logger,
    )
    test_user = add_test_user(db_session)

    # Pass in an empty pkey cache so that the client will have to hit the jwks endpoint.
    ras_client.update_user_visas(test_user, pkey_cache={})

    # Check that the new visa passed validation, indicating a successful pkey fetch
    query_visa = db_session.query(GA4GHVisaV1).first()
    assert query_visa.ga4gh_visa == encoded_visa


@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_userinfo")
@mock.patch("fence.resources.openid.ras_oauth2.RASOauth2Client.get_access_token")
@mock.patch(
    "fence.resources.openid.ras_oauth2.RASOauth2Client.get_value_from_discovery_doc"
)
def test_visa_update_cronjob(
    mock_discovery,
    mock_get_token,
    mock_userinfo,
    db_session,
    rsa_private_key,
    rsa_public_key,
    kid,
):
    """
    Test to check visa table is updated when updating visas using cronjob
    """

    n_users = 20
    n_users_no_visa = 15

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

    for i in range(n_users):
        username = "user_{}".format(i)
        test_user = add_test_user(db_session, username, i)
        add_visa_manually(db_session, test_user, rsa_private_key, kid)
        add_refresh_token(db_session, test_user)
    for j in range(n_users_no_visa):
        username = "no_visa_{}".format(j)
        test_user = add_test_user(db_session, username, j + n_users)

    query_visas = db_session.query(GA4GHVisaV1).all()

    assert len(query_visas) == n_users

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
            "type": "https://ras.nih.gov/visas/v1",
            "asserted": int(time.time()),
            "value": "https://nig/passport/dbgap",
            "source": "https://ncbi/gap",
        },
    }

    headers = {"kid": kid}

    encoded_visa = jwt.encode(
        new_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    ).decode("utf-8")

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    new_passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": "abcde12345aspdij",
        "iat": int(time.time()),
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": int(time.time()) + 1000,
        "ga4gh_passport_v1": [encoded_visa],
    }

    encoded_passport = jwt.encode(
        new_passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    ).decode("utf-8")

    userinfo_response["passport_jwt_v11"] = encoded_passport
    mock_userinfo.return_value = userinfo_response

    # test "fence-create update-visa"
    job = Visa_Token_Update()
    job.pkey_cache = {
        "https://stsstg.nih.gov": {
            kid: rsa_public_key,
        }
    }
    loop = asyncio.get_event_loop()
    loop.run_until_complete(job.update_tokens(db_session))

    query_visas = db_session.query(GA4GHVisaV1).all()

    assert len(query_visas) == n_users

    for visa in query_visas:
        assert visa.ga4gh_visa == encoded_visa
