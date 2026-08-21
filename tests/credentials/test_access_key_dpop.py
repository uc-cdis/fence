"""
Test DPoP enforcement on ``POST /credentials/api/access_token``.
"""

import pytest
from authutils.dpop import generate_dpop_proof, generate_stateless_nonce
from joserfc import jwk

from fence.config import config
from fence.jwt.validate import validate_jwt
from tests.utils.api_key import get_api_key

TASK_TOKEN_TYPE = "FOO"
DPOP_SHARED_SECRET = "test-secret-long-enough-to-sign-nonces-with"
ACCESS_TOKEN_PATH = "/credentials/api/access_token"
PROOF_URL = f"{config['BASE_URL'].rstrip('/')}{ACCESS_TOKEN_PATH}"


@pytest.fixture
def dpop_enabled(monkeypatch):
    """Turn on DPoP enforcement with a nonce-signing secret the test also knows."""
    monkeypatch.setitem(config, "DPOP_ENABLED", True)
    monkeypatch.setitem(config, "DPOP_SHARED_SECRET", DPOP_SHARED_SECRET)


@pytest.fixture
def client_key():
    """The key a DPoP client holds and signs its proofs with."""
    return jwk.ECKey.generate_key("P-256")


@pytest.fixture
def api_key(client, encoded_creds_jwt, mock_arborist_requests):
    """An API key belonging to a user who is authorized for task tokens."""
    mock_arborist_requests({"arborist/auth/request": {"POST": ({"auth": True}, 200)}})
    response = get_api_key(client, encoded_creds_jwt["jwt"])
    assert response.status_code == 200, response.text
    return response.json["api_key"]


def request_task_token(client, api_key, dpop_header=None):
    """
    Request a task token, optionally presenting a DPoP proof.

    Args:
        client: client fixture
        api_key (str): API key to exchange for an access token
        dpop_header (str | None): DPoP proof JWT to send in the ``DPoP`` header

    Return:
        pytest_flask.plugin.JSONResponse: the response from the access token endpoint
    """
    headers = {}
    if dpop_header is not None:
        headers["DPoP"] = dpop_header
    return client.post(
        f"{ACCESS_TOKEN_PATH}?task_token={TASK_TOKEN_TYPE}",
        data={"api_key": api_key},
        headers=headers,
    )


def test_issued_token_is_bound_to_the_proof_key(
    client, api_key, client_key, dpop_enabled
):
    """A valid proof yields a token whose cnf.jkt is the proof key's thumbprint."""
    proof = generate_dpop_proof(
        client_key,
        "POST",
        PROOF_URL,
        nonce=generate_stateless_nonce(DPOP_SHARED_SECRET),
    )

    response = request_task_token(client, api_key, proof)

    assert response.status_code == 200, response.text
    claims = validate_jwt(response.json["access_token"], aud=TASK_TOKEN_TYPE)
    assert claims["cnf"] == {"jkt": client_key.thumbprint()}


def test_proof_without_nonce_gets_a_nonce_challenge(
    client, api_key, client_key, dpop_enabled
):
    """A proof with no nonce is challenged with a usable nonce, per RFC 9449 8."""
    proof = generate_dpop_proof(client_key, "POST", PROOF_URL)

    response = request_task_token(client, api_key, proof)

    assert response.status_code == 400, response.text
    assert response.headers.get("DPoP-Nonce")
    assert response.json["error"] == "use_dpop_nonce"


def test_nonce_from_the_challenge_is_accepted(
    client, api_key, client_key, dpop_enabled
):
    """Retrying with the nonce the server handed back succeeds."""
    challenge = request_task_token(
        client, api_key, generate_dpop_proof(client_key, "POST", PROOF_URL)
    )
    nonce = challenge.headers["DPoP-Nonce"]

    response = request_task_token(
        client, api_key, generate_dpop_proof(client_key, "POST", PROOF_URL, nonce=nonce)
    )

    assert response.status_code == 200, response.text


def test_missing_dpop_header_is_rejected(client, api_key, dpop_enabled):
    """A task token cannot be obtained without a DPoP proof."""
    response = request_task_token(client, api_key)

    assert response.status_code == 400, response.text
    assert "access_token" not in response.text


def test_replayed_proof_is_rejected(client, api_key, client_key, dpop_enabled):
    """A proof that already bought a token cannot be used again, per RFC 9449 11.1."""
    proof = generate_dpop_proof(
        client_key,
        "POST",
        PROOF_URL,
        nonce=generate_stateless_nonce(DPOP_SHARED_SECRET),
    )

    first = request_task_token(client, api_key, proof)
    replay = request_task_token(client, api_key, proof)

    assert first.status_code == 200, first.text
    assert replay.status_code == 400, replay.text
    assert "access_token" not in replay.text


@pytest.mark.parametrize(
    ("method", "url"),
    [
        # It's actually POST - so this is wrong.
        ("GET", PROOF_URL),
        # URL is wrong
        ("POST", f"{config['BASE_URL'].rstrip('/')}/foobar/"),
    ],
    ids=["method_mismatch", "url_mismatch"],
)
def test_proof_for_a_different_request_is_rejected(
    client, api_key, client_key, dpop_enabled, method, url
):
    """A proof whose htm/htu do not match the request it accompanies is rejected."""
    proof = generate_dpop_proof(
        client_key, method, url, nonce=generate_stateless_nonce(DPOP_SHARED_SECRET)
    )

    response = request_task_token(client, api_key, proof)

    assert response.status_code == 400, response.text
    assert "access_token" not in response.text


def test_dpop_disabled_ignores_the_proof(client, api_key, client_key):
    """With DPOP_ENABLED off, a proof is neither required nor bound to the token."""
    proof = generate_dpop_proof(client_key, "POST", PROOF_URL)

    response = request_task_token(client, api_key, proof)

    assert response.status_code == 200, response.text
    claims = validate_jwt(response.json["access_token"], aud=TASK_TOKEN_TYPE)
    assert "cnf" not in claims
