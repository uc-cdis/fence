import flask
import uuid
import oauthlib
import jwt
import json

from datetime import datetime, timedelta
from flask_sqlalchemy_session import current_session

from cdispyutils import auth
from . import blacklist, errors, keys
from .blacklist import BlacklistedToken
from ..data_model import models


def issued_and_expiration_times(seconds_to_expire):
    """
    Return the times in unix time that a token is being issued and will be
    expired (the issuing time being now, and the expiration being
    ``seconds_to_expire`` seconds after that). Used for constructing JWTs.

    Args:
        seconds_to_expire (int): lifetime in seconds

    Return:
        Tuple[int, int]: (issued, expired) times in unix time
    """
    now = datetime.now()
    iat = int(now.strftime('%s'))
    exp = int((now + timedelta(seconds=seconds_to_expire)).strftime('%s'))
    return (iat, exp)


def generate_signed_refresh_token(kid, private_key, user, expires_in, scopes):
    """
    Generate a JWT refresh token from the given request, and output a UTF-8
    string of the encoded JWT signed with the private key.

    Args:
        private_key (str): RSA private key to sign and encode the JWT with
        request (oauthlib.common.Request): token request to handle

    Return:
        str: encoded JWT refresh token signed with ``private_key``
    """
    headers = {'kid': kid}
    iat, exp = issued_and_expiration_times(expires_in)
    claims = {
        'aud': ['refresh'],
        'sub': str(user.id),
        'iss': flask.current_app.config.get('HOST_NAME'),
        'iat': iat,
        'exp': exp,
        'jti': str(uuid.uuid4()),
        'access_aud': scopes,
        'context': {
            'user': {
                'name': user.username,
                'is_admin': user.is_admin,
                'projects': dict(user.project_access),
            },
        },
    }
    flask.current_app.logger.info(
        'issuing JWT refresh token\n' + json.dumps(claims, indent=4)
    )
    token = jwt.encode(claims, private_key, headers=headers, algorithm='RS256')
    token = oauthlib.common.to_unicode(token, 'UTF-8')
    return token


def generate_signed_access_token(kid, private_key, user, expires_in, scopes):
    """
    Generate a JWT refresh token from the given request, and output a UTF-8
    string of the encoded JWT signed with the private key.

    Args:
        kid: key id of the generated token
        private_key (str): RSA private key to sign and encode the JWT with
        user:
        expires_in:
        scopes

    Return:
        str: encoded JWT access token signed with ``private_key``
    """
    headers = {'kid': kid}
    iat, exp = issued_and_expiration_times(expires_in)
    claims = {
        'aud': scopes + ['access'],
        'sub': str(user.id),
        'iss': flask.current_app.config.get('HOST_NAME'),
        'iat': iat,
        'exp': exp,
        'jti': str(uuid.uuid4()),
        'context': {
            'user': {
                'name': user.username,
                'is_admin': user.is_admin,
                'projects': dict(user.project_access),
            },
        },
    }
    flask.current_app.logger.info(
        'issuing JWT access token\n' + json.dumps(claims, indent=4)
    )
    token = jwt.encode(claims, private_key, headers=headers, algorithm='RS256')
    flask.current_app.logger.info(str(token))
    return token


def validate_refresh_token(refresh_token):
    # Validate token existing.
    if not refresh_token:
        raise errors.JWTError('No token provided.')

    # Must contain just a `'refresh'` audience for a refresh token.
    decoded_jwt = auth.validate_jwt(
        encoded_token=refresh_token,
        public_key=keys.default_public_key(),
        aud={'refresh'},
        iss=flask.current_app.config['HOST_NAME'],
    )

    # Validate jti and make sure refresh token is not blacklisted.
    jti = decoded_jwt.get('jti')
    if not jti:
        errors.JWTError('Token missing jti claim.')
    with flask.current_app.db.session as session:
        if session.query(BlacklistedToken).filter_by(jti=jti).first():
            raise errors.JWTError('Token is blacklisted.')

    return decoded_jwt


def revoke_token(encoded_token):
    """
    Revoke a refresh token.

    If the operation is successful, return an empty response with a 204 status
    code. Otherwise, return error message in JSON with a 400 code.

    Return:
        Tuple[str, int]: JSON response and status code
    """

    # Try to blacklist the token; see possible exceptions raised in
    # ``blacklist_encoded_token``.
    try:
        blacklist.blacklist_encoded_token(encoded_token)
    except jwt.InvalidTokenError:
        raise errors.JWTError('invalid token', 400)
    except KeyError as e:
        msg = 'token missing claim: {}'.format(str(e))
        raise errors.JWTError(msg, 400)
    except ValueError as e:
        raise errors.JWTError(str(e), 400)
