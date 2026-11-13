"""
Fixtures for the RFC 8693 token exchange tests.
"""

import time
import uuid

import bcrypt
import jwt
import pytest

import fence.utils
from fence.config import config
from fence.models import Client, GrantType

TEST_ISSUER = "https://stsstg.nih.gov"
UNTRUSTED_ISSUER = "https://not-a-trusted-broker.example.com"

TEST_ISSUER_WITH_PATH = "https://broker.example.com/user"
TEST_SUBJECT = "abcde12345aspdij"

TOKEN_EXCHANGE_GRANT = GrantType.token_exchange.value
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_GA4GH_PASSPORT = "urn:ga4gh:params:oauth:token-type:passport"

CLIENT_SCOPES = ["openid", "user", "data"]


@pytest.fixture(scope="function")
def token_exchange_config():
    """
    Enable token exchange with three issuers: one that any client may use, one
    restricted to a single client, and one whose URL carries a path.
    """
    saved = config.get("TOKEN_EXCHANGE")
    config["TOKEN_EXCHANGE"] = {
        "enabled": True,
        "allowed_subject_token_issuers": {
            TEST_ISSUER: {
                "allowed_subject_token_types": [
                    TOKEN_TYPE_JWT,
                    TOKEN_TYPE_GA4GH_PASSPORT,
                ],
                "allowed_requested_token_types": [TOKEN_TYPE_ACCESS_TOKEN],
                "allowed_clients": [],
                "max_token_lifetime": 3600,
                "allowed_scopes": ["openid", "user"],
            },
            "https://sts.nih.gov": {
                "allowed_subject_token_types": [TOKEN_TYPE_JWT],
                "allowed_clients": ["some-other-client"],
                "max_token_lifetime": 600,
            },
            TEST_ISSUER_WITH_PATH: {
                "allowed_subject_token_types": [
                    TOKEN_TYPE_JWT,
                    TOKEN_TYPE_GA4GH_PASSPORT,
                ],
                "allowed_clients": [],
                "max_token_lifetime": 3600,
            },
        },
    }
    yield config["TOKEN_EXCHANGE"]
    config["TOKEN_EXCHANGE"] = saved


@pytest.fixture(scope="function")
def token_exchange_client(db_session):
    """
    A confidential client registered for the token exchange grant.

    The client_id and name differ, as they do for a client created with
    ``fence-create``, so that tests can tell which one ``allowed_clients``
    matches.
    """
    client_id = "test-token-exchange-client-id"
    client_name = "test-token-exchange-client"
    client_secret = fence.utils.random_str(50)
    hashed_secret = bcrypt.hashpw(
        client_secret.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
    db_session.add(
        Client(
            client_id=client_id,
            client_secret=hashed_secret,
            allowed_scopes=CLIENT_SCOPES,
            description="",
            is_confidential=True,
            name=client_name,
            grant_types=[TOKEN_EXCHANGE_GRANT],
        )
    )
    db_session.commit()
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "name": client_name,
    }


@pytest.fixture(scope="function")
def rotated_token_exchange_client(db_session, token_exchange_client):
    """
    New credentials for ``token_exchange_client``, as created by
    ``fence-create client-rotate``: a new client_id under the same name.
    """
    client_id = "test-token-exchange-client-id-rotated"
    client_secret = fence.utils.random_str(50)
    hashed_secret = bcrypt.hashpw(
        client_secret.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
    db_session.add(
        Client(
            client_id=client_id,
            client_secret=hashed_secret,
            allowed_scopes=CLIENT_SCOPES,
            description="",
            is_confidential=True,
            name=token_exchange_client["name"],
            grant_types=[TOKEN_EXCHANGE_GRANT],
        )
    )
    db_session.commit()
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "name": token_exchange_client["name"],
    }


@pytest.fixture(scope="function")
def no_grant_client(db_session):
    """
    A confidential client that is NOT registered for the token exchange grant.
    """
    client_id = "test-no-exchange-grant-client"
    client_secret = fence.utils.random_str(50)
    hashed_secret = bcrypt.hashpw(
        client_secret.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
    db_session.add(
        Client(
            client_id=client_id,
            client_secret=hashed_secret,
            allowed_scopes=CLIENT_SCOPES,
            description="",
            is_confidential=True,
            name="test-no-exchange-grant-client",
            grant_types=["client_credentials"],
        )
    )
    db_session.commit()
    return {"client_id": client_id, "client_secret": client_secret}


def make_passport(
    kid,
    rsa_private_key,
    issuer=TEST_ISSUER,
    subject=TEST_SUBJECT,
    passport_exp=None,
    visa_exp=None,
    visa_subject=None,
    visas=None,
):
    """
    Build an encoded GA4GH passport containing one RAS-style visa.

    Args:
        visa_subject (str): the ``sub`` of the visa, if it should differ from the
            passport's ``sub`` (to exercise identity resolution)
        visas (list): explicit list of encoded visas, e.g. [] for a passport with
            no usable visas

    Return:
        str: the encoded passport
    """
    now = int(time.time())
    passport_exp = passport_exp or now + 1000
    visa_exp = visa_exp or now + 1000

    if visas is None:
        visa = {
            "iss": issuer,
            "sub": visa_subject or subject,
            "iat": now,
            "exp": visa_exp,
            "scope": "openid ga4gh_passport_v1 email profile",
            "jti": str(uuid.uuid4()),
            "txn": "sapidjspa.asipidja",
            "name": "",
            "ga4gh_visa_v1": {
                "type": "https://ras.nih.gov/visas/v1.1",
                "asserted": now,
                "value": f"{issuer}/passport/dbgap/v1.1",
                "source": "https://ncbi.nlm.nih.gov/gap",
            },
            "ras_dbgap_permissions": [
                {
                    "consent_name": "Health/Medical/Biomedical",
                    "phs_id": "phs000991",
                    "version": "v1",
                    "participant_set": "p1",
                    "consent_group": "c1",
                    "role": "designated user",
                    "expiration": visa_exp,
                }
            ],
        }
        visas = [
            jwt.encode(
                visa, key=rsa_private_key, headers={"kid": kid}, algorithm="RS256"
            )
        ]

    passport = {
        "iss": issuer,
        "sub": subject,
        "iat": now,
        "exp": passport_exp,
        "scope": "openid ga4gh_passport_v1 email profile",
        "jti": str(uuid.uuid4()),
        "ga4gh_passport_v1": visas,
    }
    return jwt.encode(
        passport,
        key=rsa_private_key,
        headers={"type": "JWT", "alg": "RS256", "kid": kid},
        algorithm="RS256",
    )


def make_jwt(kid, rsa_private_key, issuer=TEST_ISSUER, subject=TEST_SUBJECT, exp=None):
    """
    Build an encoded JWT that is not a GA4GH passport.

    Return:
        str: the encoded JWT
    """
    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": subject,
        "iat": now,
        "exp": exp or now + 1000,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(
        claims,
        key=rsa_private_key,
        headers={"kid": kid},
        algorithm="RS256",
    )
