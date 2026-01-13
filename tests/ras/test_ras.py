import asyncio
import flask
import httpx
import time
import mock
import jwt
import pytest

from cdislogging import get_logger

from fence.blueprints.login.ras import RASCallback
from fence.config import config
from fence.models import (
    query_for_user,
    User,
    UpstreamRefreshToken,
    GA4GHVisaV1,
    IdentityProvider,
    IssSubPairToUser,
)
from fence.jwt.validate import validate_jwt
from fence.resources.openid.ras_oauth2 import RASOauth2Client as RASClient
from fence.resources.ga4gh.passports import get_or_create_gen3_user_from_iss_sub
from fence.errors import InternalError

from tests.utils import add_test_ras_user, TEST_RAS_USERNAME, TEST_RAS_SUB
from tests.dbgap_sync.conftest import add_visa_manually
from fence.job.access_token_updater import TokenAndAuthUpdater
import tests.utils
from tests.conftest import get_subjects_to_passports

logger = get_logger(__name__, log_level="debug")


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

    test_user = add_test_ras_user(db_session)
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

    ras_client.store_refresh_token(
        test_user, new_refresh_token, new_expire, db_session=db_session
    )

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
    mock_arborist_requests,
    no_app_context_no_public_keys,
):
    """
    Test to check visa table is updated when getting new visa
    """

    # ensure we don't actually try to reach out to external sites to refresh public keys
    def validate_jwt_no_key_refresh(*args, **kwargs):
        kwargs.update({"attempt_refresh": False})
        return validate_jwt(*args, **kwargs)

    # ensure there is no application context or cached keys
    temp_stored_public_keys = flask.current_app.jwt_public_keys
    temp_app_context = flask.has_app_context
    del flask.current_app.jwt_public_keys

    def return_false():
        return False

    flask.has_app_context = return_false

    mock_arborist_requests(
        {f"arborist/user/{TEST_RAS_USERNAME}": {"PATCH": (None, 204)}}
    )

    mock_discovery.return_value = "https://ras/token_endpoint"
    new_token = "refresh12345abcdefg"
    token_response = {
        "access_token": "abcdef12345",
        "id_token": "id12345abcdef",
        "refresh_token": new_token,
    }
    mock_get_token.return_value = token_response

    userinfo_response = {
        "sub": TEST_RAS_SUB,
        "name": "",
        "preferred_username": "someuser@era.com",
        "UID": "",
        "UserID": TEST_RAS_USERNAME,
        "email": "",
    }

    test_user = add_test_ras_user(db_session)
    existing_encoded_visa, _ = add_visa_manually(
        db_session, test_user, rsa_private_key, kid
    )
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

    # use default user and passport
    subjects_to_passports = get_subjects_to_passports(
        kid=kid, rsa_private_key=rsa_private_key
    )

    userinfo_response["passport_jwt_v11"] = subjects_to_passports[TEST_RAS_SUB][
        "encoded_passport"
    ]
    mock_userinfo.return_value = userinfo_response

    pkey_cache = {
        "https://stsstg.nih.gov": {
            kid: rsa_public_key,
        }
    }
    ras_client.update_user_authorization(
        test_user,
        pkey_cache=pkey_cache,
        db_session=db_session,
    )

    # restore public keys and context
    flask.current_app.jwt_public_keys = temp_stored_public_keys
    flask.has_app_context = temp_app_context

    query_visas = [
        item.ga4gh_visa
        for item in db_session.query(GA4GHVisaV1).filter_by(user=test_user)
    ]

    # at this point we expect the existing visa to stay around (since it hasn't expired)
    # and the new visa should also show up
    assert len(query_visas) == 2
    assert existing_encoded_visa in query_visas
    for visa in subjects_to_passports[TEST_RAS_SUB]["encoded_visas"]:
        assert visa in query_visas


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
    mock_arborist_requests,
):
    """
    Test to handle empty passport sent from RAS
    """
    mock_arborist_requests(
        {f"arborist/user/{TEST_RAS_USERNAME}": {"PATCH": (None, 204)}}
    )

    mock_discovery.return_value = "https://ras/token_endpoint"
    new_token = "refresh12345abcdefg"
    token_response = {
        "access_token": "abcdef12345",
        "id_token": "id12345abcdef",
        "refresh_token": new_token,
    }
    mock_get_token.return_value = token_response

    userinfo_response = {
        "sub": TEST_RAS_SUB,
        "name": "",
        "preferred_username": "someuser@era.com",
        "UID": "",
        "UserID": TEST_RAS_USERNAME,
        "email": "",
        "passport_jwt_v11": "",
    }
    mock_userinfo.return_value = userinfo_response

    test_user = add_test_ras_user(db_session)
    existing_encoded_visa, _ = add_visa_manually(
        db_session, test_user, rsa_private_key, kid
    )
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
    ras_client.update_user_authorization(
        test_user,
        pkey_cache=pkey_cache,
        db_session=db_session,
    )

    # at this point we expect the existing visa to stay around (since it hasn't expired)
    # but no new visas
    query_visas = [
        item.ga4gh_visa
        for item in db_session.query(GA4GHVisaV1).filter_by(user=test_user)
    ]
    assert len(query_visas) == 1
    assert existing_encoded_visa in query_visas


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
    mock_arborist_requests,
):
    """
    Test to check if the db is emptied if the ras userinfo sends back an empty visa
    """
    mock_arborist_requests(
        {f"arborist/user/{TEST_RAS_USERNAME}": {"PATCH": (None, 204)}}
    )

    mock_discovery.return_value = "https://ras/token_endpoint"
    new_token = "refresh12345abcdefg"
    token_response = {
        "access_token": "abcdef12345",
        "id_token": "id12345abcdef",
        "refresh_token": new_token,
    }
    mock_get_token.return_value = token_response

    userinfo_response = {
        "sub": TEST_RAS_SUB,
        "name": "",
        "preferred_username": "someuser@era.com",
        "UID": "",
        "UserID": TEST_RAS_USERNAME,
        "email": "",
    }

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    new_passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": TEST_RAS_SUB,
        "iat": int(time.time()),
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": int(time.time()) + 1000,
        "ga4gh_passport_v1": [],
    }
    encoded_passport = jwt.encode(
        new_passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    )

    userinfo_response["passport_jwt_v11"] = encoded_passport
    mock_userinfo.return_value = userinfo_response

    test_user = add_test_ras_user(db_session)
    existing_encoded_visa, _ = add_visa_manually(
        db_session, test_user, rsa_private_key, kid
    )
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

    ras_client.update_user_authorization(
        test_user, pkey_cache={}, db_session=db_session
    )

    # at this point we expect the existing visa to stay around (since it hasn't expired)
    # but no new visas
    query_visas = [
        item.ga4gh_visa
        for item in db_session.query(GA4GHVisaV1).filter_by(user=test_user)
    ]
    assert len(query_visas) == 1
    assert existing_encoded_visa in query_visas


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
    mock_arborist_requests,
    no_app_context_no_public_keys,
):
    """
    Test to check the following case:
    Received visa: [good1, bad2, good3]
    Processed/stored visa: [good1, good3]
    """
    mock_arborist_requests(
        {f"arborist/user/{TEST_RAS_USERNAME}": {"PATCH": (None, 204)}}
    )

    mock_discovery.return_value = "https://ras/token_endpoint"
    new_token = "refresh12345abcdefg"
    token_response = {
        "access_token": "abcdef12345",
        "id_token": "id12345abcdef",
        "refresh_token": new_token,
    }
    mock_get_token.return_value = token_response

    userinfo_response = {
        "sub": TEST_RAS_SUB,
        "name": "",
        "preferred_username": "someuser@era.com",
        "UID": "",
        "UserID": TEST_RAS_USERNAME,
        "email": "",
    }

    test_user = add_test_ras_user(db_session)
    existing_encoded_visa, _ = add_visa_manually(
        db_session, test_user, rsa_private_key, kid
    )
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
        "sub": TEST_RAS_SUB,
        "iat": int(time.time()),
        "exp": int(time.time()) + 1000,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": "jtiajoidasndokmasdl",
        "txn": "sapidjspa.asipidja",
        "name": "",
        "ga4gh_visa_v1": {
            "type": "https://ras.nih.gov/visas/v1",
            "asserted": int(time.time()),
            "value": "https://stsstg.nih.gov/passport/dbgap/v1.1",
            "source": "https://ncbi.nlm.nih.gov/gap",
        },
    }

    headers = {"kid": kid}

    encoded_visa = jwt.encode(
        new_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    )

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    new_passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": TEST_RAS_SUB,
        "iat": int(time.time()),
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": int(time.time()) + 1000,
    }
    new_passport["ga4gh_passport_v1"] = [encoded_visa, [], encoded_visa]

    encoded_passport = jwt.encode(
        new_passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    )
    userinfo_response["passport_jwt_v11"] = encoded_passport

    mock_userinfo.return_value = userinfo_response

    pkey_cache = {
        "https://stsstg.nih.gov": {
            kid: rsa_public_key,
        }
    }

    ras_client.update_user_authorization(
        test_user,
        pkey_cache=pkey_cache,
        db_session=db_session,
    )
    # at this point we expect the existing visa to stay around (since it hasn't expired)
    # and 2 new good visas
    query_visas = [
        item.ga4gh_visa
        for item in db_session.query(GA4GHVisaV1).filter_by(user=test_user)
    ]
    assert len(query_visas) == 3
    for query_visa in query_visas:
        assert query_visa == existing_encoded_visa or query_visa == encoded_visa


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
    mock_arborist_requests,
):
    """
    Test that when the RAS client's pkey cache is empty, the client's
    update_user_authorization can fetch and serialize the visa issuer's public keys and
    validate a visa using the correct key.
    """
    # ensure there is no application context or cached keys
    temp_stored_public_keys = flask.current_app.jwt_public_keys
    temp_app_context = flask.has_app_context
    del flask.current_app.jwt_public_keys

    def return_false():
        return False

    flask.has_app_context = return_false

    mock_arborist_requests(
        {f"arborist/user/{TEST_RAS_USERNAME}": {"PATCH": (None, 204)}}
    )

    mock_discovery.return_value = "https://ras/token_endpoint"
    mock_get_token.return_value = {
        "access_token": "abcdef12345",
        "id_token": "id12345abcdef",
        "refresh_token": "refresh12345abcdefg",
    }
    # New visa that will be returned by userinfo
    new_visa = {
        "iss": "https://stsstg.nih.gov",
        "sub": TEST_RAS_SUB,
        "iat": int(time.time()),
        "exp": int(time.time()) + 1000,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": "jtiajoidasndokmasdl",
        "txn": "sapidjspa.asipidja",
        "name": "",
        "ga4gh_visa_v1": {
            "type": "https://ras.nih.gov/visas/v1",
            "asserted": int(time.time()),
            "value": "https://stsstg.nih.gov/passport/dbgap/v1.1",
            "source": "https://ncbi.nlm.nih.gov/gap",
        },
    }
    headers = {"kid": kid}
    encoded_visa = jwt.encode(
        new_visa, key=rsa_private_key, headers=headers, algorithm="RS256"
    )

    passport_header = {
        "type": "JWT",
        "alg": "RS256",
        "kid": kid,
    }
    new_passport = {
        "iss": "https://stsstg.nih.gov",
        "sub": TEST_RAS_SUB,
        "iat": int(time.time()),
        "scope": "openid ga4gh_passport_v1 email profile",
        "exp": int(time.time()) + 1000,
        "ga4gh_passport_v1": [encoded_visa],
    }

    encoded_passport = jwt.encode(
        new_passport, key=rsa_private_key, headers=passport_header, algorithm="RS256"
    )

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
    test_user = add_test_ras_user(db_session)

    # Pass in an empty pkey cache so that the client will have to hit the jwks endpoint.
    ras_client.update_user_authorization(
        test_user, pkey_cache={}, db_session=db_session
    )

    # restore public keys and context
    flask.current_app.jwt_public_keys = temp_stored_public_keys
    flask.has_app_context = temp_app_context

    # Check that the new visa passed validation, indicating a successful pkey fetch
    query_visas = [
        item.ga4gh_visa
        for item in db_session.query(GA4GHVisaV1).filter_by(user=test_user)
    ]
    for visa in query_visas:
        assert visa == encoded_visa


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
    mock_arborist_requests,
    no_app_context_no_public_keys,
):
    """
    Test to check visa table is updated when updating visas using cronjob
    """
    mock_arborist_requests(
        {f"arborist/user/{TEST_RAS_USERNAME}": {"PATCH": (None, 204)}}
    )
    # reset users table
    db_session.query(User).delete()
    db_session.query(GA4GHVisaV1).delete()
    db_session.commit()

    n_users = 3
    n_users_no_visas = 2

    mock_discovery.return_value = "https://ras/token_endpoint"
    new_token = "refresh12345abcdefg"

    def _get_token_response_for_user(*args, **kwargs):
        token_response = {
            "access_token": f"{args[0].id}",
            "id_token": f"{args[0].id}-id12345abcdef",
            "refresh_token": f"{args[0].id}-refresh12345abcdefg",
        }
        return token_response

    mock_get_token.side_effect = _get_token_response_for_user

    user_id_to_ga4gh_info = {}

    for i in range(1, n_users + 1):
        username = "user_{}".format(i)
        test_user = add_test_ras_user(db_session, username, subject_id=username)
        encoded_visa, visa = add_visa_manually(
            db_session, test_user, rsa_private_key, kid, sub=username
        )
        user_id_to_ga4gh_info[str(test_user.id)] = {"encoded_visa": encoded_visa}

        passport_header = {
            "type": "JWT",
            "alg": "RS256",
            "kid": kid,
        }
        new_passport = {
            "iss": "https://stsstg.nih.gov",
            "sub": username,
            "iat": int(time.time()),
            "scope": "openid ga4gh_passport_v1 email profile",
            "exp": int(time.time()) + 1000,
            "ga4gh_passport_v1": [
                user_id_to_ga4gh_info[str(test_user.id)]["encoded_visa"]
            ],
        }

        userinfo_response = {
            "sub": username,
            "name": "",
            "preferred_username": "someuser@era.com",
            "UID": "",
            "UserID": username + "_USERNAME",
            "email": "",
        }
        encoded_passport = jwt.encode(
            new_passport,
            key=rsa_private_key,
            headers=passport_header,
            algorithm="RS256",
        )
        user_id_to_ga4gh_info[str(test_user.id)]["encoded_passport"] = encoded_passport

        userinfo_response["passport_jwt_v11"] = encoded_passport
        user_id_to_ga4gh_info[str(test_user.id)][
            "userinfo_response"
        ] = userinfo_response

        add_refresh_token(db_session, test_user)

    for j in range(1, n_users_no_visas + 1):
        username = "no_existing_visa_{}".format(j)
        test_user = add_test_ras_user(db_session, username, subject_id=username)

    query_visas = db_session.query(GA4GHVisaV1).all()

    assert len(query_visas) == n_users

    def _get_userinfo(*args, **kwargs):
        # b/c of the setup in _get_token_response_for_user we know the
        # access token will be the user.id
        return user_id_to_ga4gh_info.get(str(args[0].get("access_token", {})), {})[
            "userinfo_response"
        ]

    mock_userinfo.side_effect = _get_userinfo

    # test "fence-create update-visa"
    job = TokenAndAuthUpdater()
    job.pkey_cache = {
        "https://stsstg.nih.gov": {
            kid: rsa_public_key,
        }
    }
    loop = asyncio.get_event_loop()
    loop.run_until_complete(job.update_tokens(db_session))

    query_visas = db_session.query(GA4GHVisaV1).all()

    # this should not disturb previous manually added visas
    # and should add a new visa per user (including users without existing visas)
    assert len(query_visas) == n_users * 2

    for visa in query_visas:
        assert (
            visa.ga4gh_visa == user_id_to_ga4gh_info[str(visa.user.id)]["encoded_visa"]
        )


def test_map_iss_sub_pair_to_user_with_no_prior_DRS_access(db_session):
    """
    Test RASOauth2Client.map_iss_sub_pair_to_user when the username passed in
    (e.g. eRA username) does not already exist in the Fence database and that
    user's <iss, sub> combination has not already been mapped through a prior
    DRS access request.
    """
    # reset users table
    db_session.query(User).delete()
    db_session.commit()

    iss = "https://domain.tld"
    sub = "123_abc"
    username = "johnsmith"
    email = "johnsmith@domain.tld"
    oidc = config.get("OPENID_CONNECT", {})
    ras_client = RASClient(
        oidc["ras"],
        HTTP_PROXY=config.get("HTTP_PROXY"),
        logger=logger,
    )

    assert not query_for_user(db_session, username)
    iss_sub_pair_to_user_records = db_session.query(IssSubPairToUser).all()
    assert len(iss_sub_pair_to_user_records) == 0

    username_to_log_in = ras_client.map_iss_sub_pair_to_user(
        iss, sub, username, email, db_session=db_session
    )

    assert username_to_log_in == username
    iss_sub_pair_to_user = db_session.get(IssSubPairToUser, (iss, sub))
    assert iss_sub_pair_to_user.user.username == username
    assert iss_sub_pair_to_user.user.email == email
    iss_sub_pair_to_user_records = db_session.query(IssSubPairToUser).all()
    assert len(iss_sub_pair_to_user_records) == 1


def test_map_iss_sub_pair_to_user_with_prior_DRS_access(
    db_session, mock_arborist_requests
):
    """
    Test RASOauth2Client.map_iss_sub_pair_to_user when the username passed in
    (e.g. eRA username) does not already exist in the Fence database but that
    user's <iss, sub> combination has already been mapped to an existing user
    created during a prior DRS access request. In this case, that
    existing user's username is changed from sub+iss to the username passed
    in.
    """
    mock_arborist_requests({"arborist/user/123_abcdomain.tld": {"PATCH": (None, 204)}})

    # reset users table
    db_session.query(User).delete()
    db_session.commit()

    iss = "https://domain.tld"
    sub = "123_abc"
    username = "johnsmith"
    email = "johnsmith@domain.tld"
    oidc = config.get("OPENID_CONNECT", {})
    ras_client = RASClient(
        oidc["ras"],
        HTTP_PROXY=config.get("HTTP_PROXY"),
        logger=logger,
    )

    get_or_create_gen3_user_from_iss_sub(iss, sub, db_session=db_session)
    iss_sub_pair_to_user_records = db_session.query(IssSubPairToUser).all()
    assert len(iss_sub_pair_to_user_records) == 1
    iss_sub_pair_to_user = db_session.get(IssSubPairToUser, (iss, sub))
    assert iss_sub_pair_to_user.user.username == "123_abcdomain.tld"

    username_to_log_in = ras_client.map_iss_sub_pair_to_user(
        iss, sub, username, email, db_session=db_session
    )

    assert username_to_log_in == username
    iss_sub_pair_to_user_records = db_session.query(IssSubPairToUser).all()
    assert len(iss_sub_pair_to_user_records) == 1
    iss_sub_pair_to_user = db_session.get(IssSubPairToUser, (iss, sub))
    assert iss_sub_pair_to_user.user.username == username
    assert iss_sub_pair_to_user.user.email == email


def test_map_iss_sub_pair_to_user_with_prior_DRS_access_and_arborist_error(
    db_session, mock_arborist_requests
):
    """
    Test that RASOauth2Client.map_iss_sub_pair_to_user raises an internal error
    when Arborist fails to return a successful response.
    """
    mock_arborist_requests({"arborist/user/123_abcdomain.tld": {"PATCH": (None, 500)}})

    # reset users table
    db_session.query(User).delete()
    db_session.commit()

    iss = "https://domain.tld"
    sub = "123_abc"
    username = "johnsmith"
    email = "johnsmith@domain.tld"
    oidc = config.get("OPENID_CONNECT", {})
    ras_client = RASClient(
        oidc["ras"],
        HTTP_PROXY=config.get("HTTP_PROXY"),
        logger=logger,
    )
    get_or_create_gen3_user_from_iss_sub(iss, sub, db_session=db_session)

    with pytest.raises(InternalError):
        ras_client.map_iss_sub_pair_to_user(
            iss, sub, username, email, db_session=db_session
        )


def test_map_iss_sub_pair_to_user_with_prior_login_and_prior_DRS_access(
    db_session,
):
    """
    Test RASOauth2Client.map_iss_sub_pair_to_user when the username passed in
    (e.g. eRA username) already exists in the Fence database and that
    user's <iss, sub> combination has already been mapped to a separate user
    created during a prior DRS access request. In this case,
    map_iss_sub_pair_to_user returns the user created from prior DRS/data
    access, rendering the other user (e.g. the eRA one) inaccessible.
    """
    iss = "https://domain.tld"
    sub = "123_abc"
    username = "johnsmith"
    email = "johnsmith@domain.tld"
    oidc = config.get("OPENID_CONNECT", {})
    ras_client = RASClient(
        oidc["ras"],
        HTTP_PROXY=config.get("HTTP_PROXY"),
        logger=logger,
    )

    # reset users table
    db_session.query(User).delete()
    db_session.commit()

    user = User(username=username, email=email)
    db_session.add(user)
    db_session.commit()

    get_or_create_gen3_user_from_iss_sub(iss, sub, db_session=db_session)
    username_to_log_in = ras_client.map_iss_sub_pair_to_user(
        iss, sub, username, email, db_session=db_session
    )
    assert username_to_log_in == "123_abcdomain.tld"
    iss_sub_pair_to_user = db_session.get(IssSubPairToUser, (iss, sub))
    assert iss_sub_pair_to_user.user.username == "123_abcdomain.tld"
