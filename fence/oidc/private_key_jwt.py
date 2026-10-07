"""
Private Key JWT client authentication for SMART Backend Services (CONF-0120).

Clients register their JWKS in `client_metadata["jwks"]` and authenticate by
sending a JWT signed with their private key to the token endpoint.

Limitation: JTI replay prevention is not implemented because it requires a
shared cache (e.g. Redis) across all fence worker processes. The `exp` claim
still limits the window of reuse to the token's lifetime.
"""

from authlib.jose import JsonWebKey
from authlib.oauth2.rfc6749 import InvalidClientError
from authlib.oauth2.rfc7523.client import JWTBearerClientAssertion

from fence.config import config


class FencePrivateKeyJWT(JWTBearerClientAssertion):
    """Server-side handler for private_key_jwt client authentication.

    Registered as a client auth method on the OIDC server so that Backend
    Services clients can authenticate without a shared secret.
    """

    CLIENT_AUTH_METHOD = "private_key_jwt"

    def __init__(self):
        super().__init__(token_url=None, validate_jti=False)

    def create_claims_options(self):
        token_url = config["BASE_URL"].rstrip("/") + "/oauth2/token"
        return {
            # iss MUST equal sub per RFC 7523 §3
            "iss": {
                "essential": True,
                "validate": lambda claims, iss: claims.get("sub") == iss,
            },
            "sub": {"essential": True},
            "aud": {"essential": True, "value": token_url},
            "exp": {"essential": True},
        }

    def resolve_client_public_key(self, client, headers):
        """Look up the client's public key from its registered JWKS."""
        jwks = client.jwks
        if not jwks:
            raise InvalidClientError(
                "Client has no public keys registered. Set 'jwks' in client metadata."
            )
        key_set = JsonWebKey.import_key_set(jwks)
        kid = headers.get("kid")
        if kid:
            key = key_set.find_by_kid(kid)
            if not key:
                raise InvalidClientError(f"No key with kid={kid!r} in client JWKS")
            return key
        keys = list(key_set)
        if not keys:
            raise InvalidClientError("Client JWKS contains no keys")
        return keys[0]
