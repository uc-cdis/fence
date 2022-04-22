import json

import jwt
from jwt.algorithms import RSAAlgorithm
from jwt.utils import to_base64url_uint

from .idp_oauth2 import Oauth2ClientBase
from ...config import config


class SynapseOauth2Client(Oauth2ClientBase):
    """
    client for interacting with Synapse OAuth2,
    as OpenID Connect is supported under OAuth2

    """

    REQUIRED_CLAIMS = {"given_name", "family_name", "email", "email_verified", "userid"}
    OPTIONAL_CLAIMS = {
        # "company",
        # "orcid",
        # "is_certified",
        # "is_validated",
        "validated_given_name",
        "validated_family_name",
        # "validated_location",
        "validated_email",
        # "validated_company",
        # "validated_orcid",
        # "validated_at",
    }
    SYSTEM_CLAIMS = {"sub", "exp"}
    CUSTOM_CLAIMS = {"team"}

    def __init__(self, settings, logger, HTTP_PROXY=None):
        super(SynapseOauth2Client, self).__init__(
            settings,
            logger,
            scope=settings.get("scope") or "openid",
            # The default discovery URL on Synapse staging is not serving the correct
            # info. Providing a workaround here for overwriting.
            discovery_url=settings.get("discovery_url")
            or config["SYNAPSE_DISCOVERY_URL"]
            or (config["SYNAPSE_URI"] + "/.well-known/openid-configuration"),
            idp="Synapse",
            HTTP_PROXY=HTTP_PROXY,
        )

    def get_auth_url(self):
        """
        Get authorization uri from discovery doc
        """
        authorization_endpoint = self.get_value_from_discovery_doc(
            "authorization_endpoint", config["SYNAPSE_URI"] + "/oauth2/authorize"
        )

        claims = dict(
            id_token=dict(
                team=dict(values=[config["DREAM_CHALLENGE_TEAM"]]),
                **{
                    claim: dict(essential=claim in self.REQUIRED_CLAIMS)
                    for claim in self.REQUIRED_CLAIMS | self.OPTIONAL_CLAIMS
                }
            )
        )
        uri, state = self.session.create_authorization_url(
            authorization_endpoint,
            prompt="login",
            claims=json.dumps(claims, separators=(",", ": ")),
        )

        return uri

    def load_key(self, jwks_endpoint):
        """
        A custom method to load a Synapse "RS256" key.

        Synapse is not providing standard JWK keys:
        * kty is RS256 not RSA
        * e and n are not base64-encoded

        Synapse is updating their JWKS document to align it with conventions,
        so above logic could be abandoned in the future.
        """
        for key in self.get_jwt_keys(jwks_endpoint):
            # For new Synapse JWKS doc, which is modified with conventions
            if key["kty"] == "RSA":
                return "RS256", RSAAlgorithm.from_jwk(json.dumps(key))
            # For old Synapse JWKS odc, kept for backward compability
            # TODO: remove after tested with new Synapse JWKS doc
            # and Synapse has deployed their changes
            elif key["kty"] == "RS256":
                key["kty"] = "RSA"
                for field in ["e", "n"]:
                    if key[field].isdigit():
                        key[field] = to_base64url_uint(int(key[field])).decode()
                return "RS256", RSAAlgorithm.from_jwk(json.dumps(key))

        return None, None

    def get_user_id(self, code):
        try:
            token_endpoint = self.get_value_from_discovery_doc(
                "token_endpoint", config["SYNAPSE_URI"] + "/oauth2/token"
            )
            # For testing new Synapse JWKS doc (if pinned to new JWKS doc)
            # or avoid downtime (if pinned to old JWKS doc)
            # TODO: can be removed after tested with new Synapse JWKS doc
            # and Synapse has deployed their changes
            if config["SYNAPSE_JWKS_URI"]:
                jwks_endpoint = config["SYNAPSE_JWKS_URI"]
            else:
                jwks_endpoint = self.get_value_from_discovery_doc(
                    "jwks_uri", config["SYNAPSE_URI"] + "/oauth2/jwks"
                )
            token = self.get_token(token_endpoint, code)
            algorithm, key = self.load_key(jwks_endpoint)
            if not key:
                return dict(error="Cannot load JWK keys")

            claims = jwt.decode(
                token["id_token"],
                key,
                options={"verify_aud": False, "verify_at_hash": False},
                algorithms=[algorithm],
            )

            if not claims.get("email_verified"):
                return dict(error="Email is not verified")

            rv = {}
            none = object()
            for claim in (
                self.REQUIRED_CLAIMS
                | self.OPTIONAL_CLAIMS
                | self.SYSTEM_CLAIMS
                | self.CUSTOM_CLAIMS
            ):
                value = claims.get(claim, none)
                if value is none:
                    if claim not in self.OPTIONAL_CLAIMS:
                        return dict(error="Required claim {} not found".format(claim))
                else:
                    rv[claim] = value
            rv["fence_username"] = rv["userid"] + " (Synapse ID)"
            return rv
        except Exception as e:
            self.logger.exception("Can't get user info")
            return {"error": "Can't get ID token: {}".format(e)}
