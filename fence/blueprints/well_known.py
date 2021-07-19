"""
This blueprint defines the endpoints under ``.well-known/``, which includes:
- OIDC provider configuration
- JWK endpoint ``/jwks``
"""

import flask

from fence.models import ClientAuthType
from fence.config import config


blueprint = flask.Blueprint(".well-known", __name__)


@blueprint.route("/jwks", methods=["GET"])
def jwks():
    """
    Return the JWK set currently in use by fence.

    The return value from this endpoint is defined by RFC 7517.
    """
    keys = [keypair.public_key_to_jwk() for keypair in flask.current_app.keypairs]
    return flask.jsonify({"keys": keys})


@blueprint.route("/openid-configuration")
def openid_configuration():
    """
    Return the OIDC provider configuration describing fence.

    The return from this endpoint is defined by the OIDC Discovery
    specification. See the OIDC documentation for explanation of the fields
    returned from this function:

    https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata

    For an example implementation, this is the URL for the OIDC configuration
    for Google's identity platform:

    https://accounts.google.com/.well-known/openid-configuration
    """

    # Get basic provider information.
    oidc_iss = (
        config.get("OPENID_CONNECT", {}).get("fence", {}).get("api_base_url", None)
    )
    issuer = oidc_iss or config["BASE_URL"]

    # "Subject type" means the method used to assign the ``sub`` field in JWTs.
    # Fence sets the ``sub`` field to the user ID, so ``sub`` is the same
    # across all clients for the same user, meaning that the subject type is
    # "public" (all clients see the same one).
    #
    # Docs here:
    # http://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
    subject_types_supported = ["public"]

    # Get various (absolute) URLs relevant for OAuth2/OIDC.
    path_to = lambda url: config["BASE_URL"].strip("/") + url
    jwks_uri = path_to(flask.url_for(".jwks"))
    authorization_endpoint = path_to(flask.url_for("oauth2.authorize"))
    token_endpoint = path_to(flask.url_for("oauth2.get_token"))
    userinfo_endpoint = path_to(flask.url_for("user.user_info"))
    registration_endpoint = None  # not yet supported

    # List all the scopes allowed in OAuth2 requests.
    scopes_supported = list(
        set(config["USER_ALLOWED_SCOPES"] + config["CLIENT_ALLOWED_SCOPES"])
    )

    # List of all the claims which fence MAY set in the ID token.
    claims_supported = [
        "aud",
        "sub",
        "iss",
        "exp",
        "jti",
        "auth_time",
        "azp",
        "scope",
        "nonce",
        "context",
    ]

    return flask.jsonify(
        {
            "issuer": issuer,
            "authorization_endpoint": authorization_endpoint,
            "token_endpoint": token_endpoint,
            "userinfo_endpoint": userinfo_endpoint,
            "registration_endpoint": registration_endpoint,
            "jwks_uri": jwks_uri,
            "scopes_supported": scopes_supported,
            "response_types_supported": ["openid", "code", "token"],
            "response_modes_supported": [],
            "grant_types_supported": ["authorization_code", "implicit"],
            "subject_types_supported": subject_types_supported,
            "id_token_signing_alg_values_supported": ["RS256"],
            "id_token_encryption_alg_values_supported": [],
            "id_token_encryption_enc_values_supported": [],
            "request_object_signing_alg_values_supported": [],
            "request_object_encryption_alg_values_supported": [],
            "request_object_encryption_enc_values_supported": [],
            "token_endpoint_auth_methods_supported": [ClientAuthType.basic.value],
            "display_values_supported": ["page"],
            "claim_types_supported": ["normal"],
            "claims_supported": claims_supported,
            "service_documentation": "https://github.com/uc-cdis/fence/",
            "claims_locales_supported": ["en"],
            "ui_locales_supported": ["en"],
            "claims_parameter_supported": False,
            "request_parameter_supported": False,
            "request_uri_parameter_supported": False,
            "require_request_uri_registration": False,
            "op_policy_url": None,
            "op_tos_uri": None,
        }
    )
