import flask
import uuid
import oauthlib
import jwt
import json
import blacklist

from datetime import datetime, timedelta
from flask_sqlalchemy_session import current_session
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


def generate_signed_refresh_token(kid, private_key, user, expires_in):
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
        'context': {
            'user': {
                'name': user.username,
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
        private_key (str): RSA private key to sign and encode the JWT with
        request (oauthlib.common.Request): token request to handle

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


def load_token(access_token=None, refresh_token=None):
    if access_token:
        return (
            current_session
            .query(models.Token)
            .filter_by(access_token=access_token)
            .first()
        )
    elif refresh_token:
        return (
            current_session
            .query(models.Token)
            .filter_by(refresh_token=refresh_token)
            .first()
        )


def list_tokens(user):
    return (
        current_session.query(models.Token).filter_by(user_id=user.id).all()
    )


def save_token(token, client_id, user_id, *args, **kwargs):
    toks = current_session.query(models.Token).filter_by(
        client_id=client_id,
        user_id=user_id)
    # make sure that every client has only one token connected to a user
    for t in toks:
        current_session.delete(t)

    expires_in = token.get('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = models.Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=client_id,
        user_id=user_id,
    )
    current_session.add(tok)
    current_session.commit()
    return tok


def authorize(method, confirm, **kwargs):
    if method == 'GET':
        client_id = kwargs.get('client_id')
        client = (
            current_session
            .query(models.Client)
            .filter_by(client_id=client_id)
            .first()
        )
        if client.auto_approve:
            return True, None
        return False, client
    return confirm == 'yes', None


def access_token(*args, **kwargs):
    """
    Handle exchanging and refreshing the access token.

    The operation here is handled entirely by the ``oauth.token_handler``
    decorator, so this function only needs to pass.
    """
    pass


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
        return (flask.jsonify({'errors': 'invalid token'}), 400)
    except KeyError as e:
        msg = 'token missing claim: {}'.format(str(e))
        return (flask.jsonify({'errors': msg}), 400)
    except ValueError as e:
        return (flask.jsonify({'errors': str(e)}), 400)

    return ('', 204)
