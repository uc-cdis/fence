from authlib.oauth2.rfc6749.grants import (
    ClientCredentialsGrant as BaseClientCredentialsGrant,
)


class ClientCredentialsGrant(BaseClientCredentialsGrant):
    # Extend the default ["client_secret_basic"] to also accept private_key_jwt
    # so that SMART Backend Services clients can authenticate asymmetrically
    # (CONF-0120).
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "private_key_jwt"]
