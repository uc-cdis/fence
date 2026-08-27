"""
Tests for the RFC 8693 token exchange grant.

https://datatracker.ietf.org/doc/html/rfc8693
"""

import time
from unittest.mock import patch

import httpx
import flask
import jwt
import pytest

import tests.utils.oauth2
from fence.config import config
from fence.models import User
from tests.rfc8693.conftest import (
    TEST_ISSUER,
    TEST_ISSUER_WITH_PATH,
    TEST_SUBJECT,
    TOKEN_EXCHANGE_GRANT,
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_GA4GH_PASSPORT,
    TOKEN_TYPE_JWT,
    UNTRUSTED_ISSUER,
    make_passport,
)

PATH_TOKEN = "/oauth2/token"


def exchange(client, exchange_client, **params):
    """
    POST a token exchange request to the token endpoint.

    Args:
        client (werkzeug.test.Client): flask test client
        exchange_client (dict): client_id/client_secret of the OAuth client
        params: form parameters, which override the token-exchange defaults

    Return:
        the flask test response
    """
    data = {"grant_type": TOKEN_EXCHANGE_GRANT}
    data.update(params)
    data = {k: v for k, v in data.items() if v is not None}
    return client.post(
        PATH_TOKEN,
        data=data,
        headers=tests.utils.oauth2.create_basic_header(
            exchange_client["client_id"], exchange_client["client_secret"]
        ),
    )


@pytest.fixture(scope="function")
def synced_passport(
    mock_arborist_requests, mock_httpx_get_jwks, google_proxy_group, kid
):
    """
    Everything the passport sync touches, mocked out.
    """
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    yield


@pytest.fixture(scope="function")
def mock_httpx_get_jwks(app):
    """
    Serve Fence's own JWKS for any issuer's key lookup, so that passports signed
    with the test keypair validate.
    """
    keys = [keypair.public_key_to_jwk() for keypair in flask.current_app.keypairs]
    with patch("httpx.get") as mock_get:
        mock_get.return_value = httpx.Response(200, json={"keys": keys})
        yield mock_get


class TestRequestValidation:
    """
    Request-shape and policy checks, none of which should reach the passport
    sync.
    """

    def test_disabled_by_default(
        self, client, token_exchange_client, kid, rsa_private_key
    ):
        """Token exchange is off unless TOKEN_EXCHANGE.enabled is set."""
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key),
            subject_token_type=TOKEN_TYPE_JWT,
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "unsupported_grant_type"

    def test_client_without_grant(
        self, client, token_exchange_config, no_grant_client, kid, rsa_private_key
    ):
        """A client not registered for the grant cannot use it."""
        response = exchange(
            client,
            no_grant_client,
            subject_token=make_passport(kid, rsa_private_key),
            subject_token_type=TOKEN_TYPE_JWT,
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "unauthorized_client"

    def test_missing_subject_token(
        self, client, token_exchange_config, token_exchange_client
    ):
        response = exchange(
            client, token_exchange_client, subject_token_type=TOKEN_TYPE_JWT
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_request"

    def test_missing_subject_token_type(
        self, client, token_exchange_config, token_exchange_client, kid, rsa_private_key
    ):
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key),
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_request"

    def test_actor_token_rejected(
        self, client, token_exchange_config, token_exchange_client, kid, rsa_private_key
    ):
        """Delegation is not supported (RFC 8693 section 2.1)."""
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key),
            subject_token_type=TOKEN_TYPE_JWT,
            actor_token="some-other-token",
            actor_token_type=TOKEN_TYPE_JWT,
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_request"

    @pytest.mark.parametrize("target_param", ["audience", "resource"])
    def test_target_rejected(
        self,
        client,
        token_exchange_config,
        token_exchange_client,
        kid,
        rsa_private_key,
        target_param,
    ):
        """RFC 8693 section 2.2.2: invalid_target for an unsupported target."""
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key),
            subject_token_type=TOKEN_TYPE_JWT,
            **{target_param: "http://localhost/some-service"},
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_target"

    def test_untrusted_issuer(
        self, client, token_exchange_config, token_exchange_client, kid, rsa_private_key
    ):
        """
        A passport from an issuer that is not allowlisted is rejected, and the
        error does not name the issuer or the allowlist.
        """
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key, issuer=UNTRUSTED_ISSUER),
            subject_token_type=TOKEN_TYPE_JWT,
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_grant"
        assert UNTRUSTED_ISSUER not in response.json.get("error_description", "")

    def test_untrusted_issuer_fetches_no_keys(
        self,
        client,
        token_exchange_config,
        token_exchange_client,
        mock_httpx_get_jwks,
        kid,
        rsa_private_key,
    ):
        """
        The issuer check happens before any key resolution, so an untrusted
        issuer never causes an outbound request.
        """
        exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key, issuer=UNTRUSTED_ISSUER),
            subject_token_type=TOKEN_TYPE_JWT,
        )
        assert not mock_httpx_get_jwks.called

    def test_subject_token_type_not_allowed_for_issuer(
        self, client, token_exchange_config, token_exchange_client, kid, rsa_private_key
    ):
        """
        The configured issuer allows only JWT/passport subject tokens, not
        access tokens.
        """
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key),
            subject_token_type=TOKEN_TYPE_ACCESS_TOKEN,
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_request"

    def test_client_not_allowed_for_issuer(
        self, client, token_exchange_config, token_exchange_client, kid, rsa_private_key
    ):
        """
        The 'https://sts.nih.gov' policy restricts exchange to one other client.
        """
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(
                kid, rsa_private_key, issuer="https://sts.nih.gov"
            ),
            subject_token_type=TOKEN_TYPE_JWT,
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "unauthorized_client"

    def test_unsupported_requested_token_type(
        self, client, token_exchange_config, token_exchange_client, kid, rsa_private_key
    ):
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key),
            subject_token_type=TOKEN_TYPE_JWT,
            requested_token_type="urn:ietf:params:oauth:token-type:refresh_token",
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_request"

    def test_malformed_subject_token(
        self, client, token_exchange_config, token_exchange_client
    ):
        response = exchange(
            client,
            token_exchange_client,
            subject_token="not-a-jwt",
            subject_token_type=TOKEN_TYPE_JWT,
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_request"

    def test_scope_beyond_issuer_policy(
        self,
        client,
        token_exchange_config,
        token_exchange_client,
        mock_httpx_get_jwks,
        kid,
        rsa_private_key,
    ):
        """
        'data' is allowed for the client but not by the issuer's policy, so it
        cannot be granted.
        """
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key),
            subject_token_type=TOKEN_TYPE_JWT,
            scope="openid data",
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_scope"


@patch("fence.resources.google.utils._create_proxy_group")
@patch("fence.scripting.fence_create.ArboristClient")
class TestTokenIssuance:
    """
    The happy path and the properties of the token it returns.
    """

    def test_exchange_passport_for_access_token(
        self,
        mock_arborist,
        mock_google_proxy_group,
        client,
        db_session,
        token_exchange_config,
        token_exchange_client,
        synced_passport,
        google_proxy_group,
        kid,
        rsa_private_key,
    ):
        mock_google_proxy_group.return_value = google_proxy_group
        passport = make_passport(kid, rsa_private_key)

        response = exchange(
            client,
            token_exchange_client,
            subject_token=passport,
            subject_token_type=TOKEN_TYPE_JWT,
        )

        assert response.status_code == 200, response.json
        body = response.json

        # RFC 8693 section 2.2.1
        assert "access_token" in body
        assert body["issued_token_type"] == TOKEN_TYPE_ACCESS_TOKEN
        assert body["token_type"] == "Bearer"
        assert "expires_in" in body
        # a refresh token would outlive the visas that justified the exchange
        assert "refresh_token" not in body

        claims = jwt.decode(
            body["access_token"],
            options={"verify_signature": False},
            algorithms=["RS256"],
        )
        assert claims["iss"] == config["BASE_URL"]
        assert claims["azp"] == token_exchange_client["client_id"]
        assert claims["pur"] == "access"

        # identity came from the passport's own <iss, sub>
        user = db_session.query(User).filter_by(id=int(claims["sub"])).first()
        assert user is not None
        assert user.username == TEST_SUBJECT + TEST_ISSUER[len("https://") :]

    def test_passport_token_type_urn_accepted(
        self,
        mock_arborist,
        mock_google_proxy_group,
        client,
        token_exchange_config,
        token_exchange_client,
        synced_passport,
        google_proxy_group,
        kid,
        rsa_private_key,
    ):
        """The GA4GH-specific subject token type identifier also works."""
        mock_google_proxy_group.return_value = google_proxy_group
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key),
            subject_token_type=TOKEN_TYPE_GA4GH_PASSPORT,
        )
        assert response.status_code == 200, response.json

    def test_scope_is_downscoped(
        self,
        mock_arborist,
        mock_google_proxy_group,
        client,
        token_exchange_config,
        token_exchange_client,
        synced_passport,
        google_proxy_group,
        kid,
        rsa_private_key,
    ):
        """
        With no scope requested, the granted scope is the intersection of the
        client's scopes and the issuer policy's -- not the client's full set.
        """
        mock_google_proxy_group.return_value = google_proxy_group
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key),
            subject_token_type=TOKEN_TYPE_JWT,
        )
        assert response.status_code == 200, response.json
        assert sorted(response.json["scope"].split(" ")) == ["openid", "user"]

    def test_requested_scope_is_honored(
        self,
        mock_arborist,
        mock_google_proxy_group,
        client,
        token_exchange_config,
        token_exchange_client,
        synced_passport,
        google_proxy_group,
        kid,
        rsa_private_key,
    ):
        mock_google_proxy_group.return_value = google_proxy_group
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key),
            subject_token_type=TOKEN_TYPE_JWT,
            scope="openid",
        )
        assert response.status_code == 200, response.json
        assert response.json["scope"] == "openid"

    def test_lifetime_clamped_by_issuer_policy(
        self,
        mock_arborist,
        mock_google_proxy_group,
        client,
        token_exchange_config,
        token_exchange_client,
        synced_passport,
        google_proxy_group,
        kid,
        rsa_private_key,
    ):
        """max_token_lifetime caps the issued token even when everything else
        allows longer."""
        mock_google_proxy_group.return_value = google_proxy_group
        token_exchange_config["allowed_subject_token_issuers"][TEST_ISSUER][
            "max_token_lifetime"
        ] = 60

        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(
                kid, rsa_private_key, passport_exp=int(time.time()) + 100000
            ),
            subject_token_type=TOKEN_TYPE_JWT,
        )
        assert response.status_code == 200, response.json
        assert response.json["expires_in"] == 60

    def test_lifetime_clamped_by_visa_expiration(
        self,
        mock_arborist,
        mock_google_proxy_group,
        client,
        token_exchange_config,
        token_exchange_client,
        synced_passport,
        google_proxy_group,
        kid,
        rsa_private_key,
    ):
        """
        A visa expiring sooner than the configured lifetime shortens the issued
        token.
        """
        mock_google_proxy_group.return_value = google_proxy_group
        visa_lifetime = config["EXPIRED_AUTHZ_REMOVAL_JOB_FREQ_IN_SECONDS"] + 400
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(
                kid, rsa_private_key, visa_exp=int(time.time()) + visa_lifetime
            ),
            subject_token_type=TOKEN_TYPE_JWT,
        )
        assert response.status_code == 200, response.json
        # the sync subtracts the authz removal job frequency from the earliest
        # visa expiration
        assert response.json["expires_in"] <= 400
        assert response.json["expires_in"] > 300

    def test_passport_without_usable_visas(
        self,
        mock_arborist,
        mock_google_proxy_group,
        client,
        token_exchange_config,
        token_exchange_client,
        synced_passport,
        google_proxy_group,
        kid,
        rsa_private_key,
    ):
        mock_google_proxy_group.return_value = google_proxy_group
        response = exchange(
            client,
            token_exchange_client,
            subject_token=make_passport(kid, rsa_private_key, visas=[]),
            subject_token_type=TOKEN_TYPE_JWT,
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_grant"

    def test_visas_for_a_different_subject(
        self,
        mock_arborist,
        mock_google_proxy_group,
        client,
        db_session,
        token_exchange_config,
        token_exchange_client,
        synced_passport,
        google_proxy_group,
        kid,
        rsa_private_key,
    ):
        """
        Identity comes from the passport's <iss, sub>, so a passport whose visas
        assert a different subject would produce a token with no authorization.
        require_passport_subject_visa_match rejects it instead.
        """
        mock_google_proxy_group.return_value = google_proxy_group
        passport = make_passport(
            kid, rsa_private_key, visa_subject="some-other-subject"
        )
        passport_subject_username = TEST_SUBJECT + TEST_ISSUER[len("https://") :]

        response = exchange(
            client,
            token_exchange_client,
            subject_token=passport,
            subject_token_type=TOKEN_TYPE_JWT,
        )
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_grant"
        # a rejected exchange must not leave a user behind
        assert (
            db_session.query(User).filter_by(username=passport_subject_username).first()
            is None
        )

        # with the check off, the exchange succeeds for the passport subject
        token_exchange_config["allowed_subject_token_issuers"][TEST_ISSUER][
            "require_passport_subject_visa_match"
        ] = False
        response = exchange(
            client,
            token_exchange_client,
            subject_token=passport,
            subject_token_type=TOKEN_TYPE_JWT,
        )
        assert response.status_code == 200, response.json


class TestIssuerKeyResolution:
    """
    Which URL Fence fetches a subject token issuer's public keys from.

    ``authutils.token.core.get_keys_url`` derives that URL from the issuer
    string alone: it tries ``<iss>/.well-known/openid-configuration`` and uses
    the ``jwks_uri`` it advertises, falling back to ``<iss>/jwt/keys`` if that
    request fails or advertises nothing. An issuer whose URL carries a path is
    therefore only resolvable if the path survives into the key URL, and getting
    it wrong looks identical to a missing key at the call site.

    The other tests here mock ``httpx.get`` to answer any URL, so they cannot
    tell a correct key URL from a wrong one. These assert the URL directly.

    Both cases stop at key lookup: the served JWKS deliberately omits the
    passport's kid, so the exchange fails with ``invalid_grant`` after the keys
    are fetched but before any sync.
    """

    #: A key set that resolves (``get_pem_key`` treats a [kid, pem] pair with no
    #: 'kty' as already-PEM) but does not contain the kid the passport is signed
    #: with, so no signature is ever verified against it.
    JWKS_WITHOUT_TEST_KID = {
        "keys": [
            [
                "some-other-kid",
                "-----BEGIN PUBLIC KEY-----\nnot-a-real-key\n-----END PUBLIC KEY-----\n",
            ]
        ]
    }

    @staticmethod
    def _exchange_recording_urls(client, exchange_client, passport, responder):
        """
        Run an exchange with ``httpx.get`` patched to answer via ``responder``,
        recording every URL requested.

        Args:
            responder (Callable[[str], httpx.Response]): given a URL, return the
                response to serve for it
        Return:
            tuple: (list of requested URLs, the flask test response)
        """
        requested = []

        def fake_get(url, *args, **kwargs):
            requested.append(str(url))
            return responder(str(url))

        try:
            with patch("httpx.get", side_effect=fake_get):
                response = exchange(
                    client,
                    exchange_client,
                    subject_token=passport,
                    subject_token_type=TOKEN_TYPE_JWT,
                )
            return requested, response
        finally:
            # the app fixture outlives this test; don't leave the mock issuer's
            # keys cached on it
            flask.current_app.jwt_public_keys.pop(TEST_ISSUER_WITH_PATH, None)

    def test_key_url_falls_back_to_jwt_keys_under_issuer_path(
        self, client, token_exchange_config, token_exchange_client, kid, rsa_private_key
    ):
        """
        With no discovery document, the keys are fetched from '/jwt/keys'
        beneath the full issuer URL -- not beneath its host, which is the
        failure this pins down.
        """

        def responder(url):
            if url.endswith("/.well-known/openid-configuration"):
                return httpx.Response(404, text="not found")
            return httpx.Response(200, json=self.JWKS_WITHOUT_TEST_KID)

        requested, response = self._exchange_recording_urls(
            client,
            token_exchange_client,
            make_passport(kid, rsa_private_key, issuer=TEST_ISSUER_WITH_PATH),
            responder,
        )

        assert requested == [
            f"{TEST_ISSUER_WITH_PATH}/.well-known/openid-configuration",
            f"{TEST_ISSUER_WITH_PATH}/jwt/keys",
        ]
        # reached key lookup rather than failing earlier for another reason
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_grant"

    def test_key_url_uses_jwks_uri_from_discovery(
        self, client, token_exchange_config, token_exchange_client, kid, rsa_private_key
    ):
        """
        When the issuer serves a discovery document, its 'jwks_uri' is used
        as-is and the '/jwt/keys' fallback is not requested.
        """
        jwks_uri = "https://keys.example.com/some/other/location"

        def responder(url):
            if url.endswith("/.well-known/openid-configuration"):
                return httpx.Response(
                    200,
                    json={"issuer": TEST_ISSUER_WITH_PATH, "jwks_uri": jwks_uri},
                )
            return httpx.Response(200, json=self.JWKS_WITHOUT_TEST_KID)

        requested, response = self._exchange_recording_urls(
            client,
            token_exchange_client,
            make_passport(kid, rsa_private_key, issuer=TEST_ISSUER_WITH_PATH),
            responder,
        )

        assert requested == [
            f"{TEST_ISSUER_WITH_PATH}/.well-known/openid-configuration",
            jwks_uri,
        ]
        assert f"{TEST_ISSUER_WITH_PATH}/jwt/keys" not in requested
        assert response.status_code == 400, response.json
        assert response.json["error"] == "invalid_grant"


class TestDiscovery:
    def test_grant_advertised_when_enabled(self, client, token_exchange_config):
        response = client.get("/.well-known/openid-configuration")
        assert TOKEN_EXCHANGE_GRANT in response.json["grant_types_supported"]

    def test_grant_not_advertised_when_disabled(self, client):
        response = client.get("/.well-known/openid-configuration")
        assert TOKEN_EXCHANGE_GRANT not in response.json["grant_types_supported"]
