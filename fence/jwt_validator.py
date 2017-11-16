import datetime

import flask
import flask_oauthlib
import jwt


def decode_signed_token(token, public_key=None):
    """
    Decode a JWT (in string form), which should have been previously signed by
    the server, into JSON.

    Args:
        token (str): the JWT to decode
        public_key (Optional[str]): key to decode the JWT with

    Return:
        dict: JWT decoded into JSON

    Raises:
        KeyError: if flask app was not configured with public key
    """
    if public_key is None:
        public_key = flask.current_app.config['JWT_PUBLIC_KEY']
    return jwt.decode(token, public_key, algorithm='RS256')


class JWTValidator(flask_oauthlib.provider.OAuth2RequestValidator):
    """
    Validator for JWTs used in the OAuth2 procedure. This class provides a
    validator for Flask's OAuth component, redefining bearer and refresh token
    validation of ``flask_oauthlib.oauth2.OAuth2RequestValidator`` to use JWT
    instead.

    .. code-block:: python

        oauth = OAuth2Provider()
        oauth._validator = JWTValidator()

    An example JWT following the specifications for this implementation:

    .. code-block:: python

        {
            "sub": "1234567",
            "iss": "dcfauth:56fc3842ccf2c1c7ec5c5d14",
            "iat": 1459458458,
            "exp": 1459487258,
            "jti": "f8733984-8164-4689-9c25-56707962d7e0",
            "aud": [
                "data",
                "iam",
            ],
            "context": {
                "user": {
                    "name": "NIH_USERNAME",
                    "projects": {
                        "phs000178": ["member"],
                        "phs000218": ["member", "submitter"],
                    },
                    "email": "user@university.edu",
                }
            }
        }
    """

    def validate_bearer_token(self, token, scopes, request):
        """
        Define ``flask_oauthlib.oauth2.OAuth2Provider.validate_bearer_token``
        to validate a JWT.

        Per `flask_oauthlib`, validate:
        #. if the token is available
        #. if the token has expired
        #. if the scopes are available

        Args:
            token (str): in this implementation, an encoded JWT
            scopes (TODO): TODO
            request (oauthlib.common.Request): TODO

        Return:
            bool: whether token is valid
        """
        # Validate token existing.
        if not token:
            msg = 'No token provided.'
            request.error_message = msg
            print(msg)
            return False

        decoded_jwt = decode_signed_token(token)

        # Validate expiration.
        expiration = decoded_jwt.get('exp', False)
        if not expiration or datetime.datetime.utcnow() >= expiration:
            msg = 'Token is expired.'
            request.error_message = msg
            print(msg)
            return False

        # TODO: check scopes?

        return True

    def validate_refresh_token(
            self, refresh_token, client, request, *args, **kwargs):
        """
        Validate a JWT refresh token.

        Args:
            refresh_token (str): encoded JWT refresh token
            client (TODO): TODO
            request (oauthlib.common.Request): TODO

        Return:
            bool: whether token is valid
        """
        # Validate token existing.
        if not refresh_token:
            msg = 'No token provided.'
            request.error_message = msg
            print(msg)
            return False

        decoded_jwt = decode_signed_token(refresh_token)

        # Validate expiration.
        expiration = decoded_jwt.get('exp', False)
        if not expiration or datetime.datetime.utcnow() >= expiration:
            msg = 'Token is expired.'
            request.error_message = msg
            print(msg)
            return False

        # TODO: check scopes?

        return True
