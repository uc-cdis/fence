from flask import current_app as cur_app
from fence.errors import Unauthorized
from fence.data_model.models import UserRefreshToken
from fence.jwt import token, errors, blacklist
from fence.auth import get_user_from_token


def create_refresh_token(user, keypair, expires_in, scopes, client_id):
    return_token, claims = token.generate_signed_refresh_token(keypair.kid, keypair.private_key,
                                                               user, expires_in, scopes, client_id)
    with cur_app.db.session as session:
        session.add(UserRefreshToken(jti=claims["jti"], userid=user.id, expires=claims["exp"]))
        session.commit()
    return return_token, claims["jti"]


def create_session_token(
        keypair, expires_in, username=None, session_started=None,
        provider=None, redirect=None):
    return token.generate_signed_session_token(keypair.kid, keypair.private_key,
                                               expires_in, username,
                                               session_started, provider, redirect)


def create_user_access_token(keypair, api_key, expires_in):
    """
    create access token given a user's api key
    Args:
        keypair: RSA keypair for signing jwt
        api_key: user created jwt token, the azp should match with user.id
        expires_in: expiration time in seconds
    Return:
        access token
    """
    try:
        decoded_jwt = token.validate_refresh_token(api_key)
        user_id = decoded_jwt['sub']
        if decoded_jwt['azp'] != user_id:
            raise Unauthorized("Only user can request user access token")
        scopes = decoded_jwt["access_aud"]
        user = get_user_from_token(decoded_jwt)
    except Exception as e:
        raise Unauthorized(e.message)
    return token.generate_signed_access_token(
        keypair.kid, keypair.private_key, user, expires_in, scopes, user_id)


def create_access_token(keypair, refresh_token, expires_in, client_id):
    try:
        decoded_jwt = token.validate_refresh_token(refresh_token)
        scopes = decoded_jwt["access_aud"]
        user = get_user_from_token(decoded_jwt)
    except Exception as e:
        raise Unauthorized(e.message)
    return token.generate_signed_access_token(keypair.kid, keypair.private_key, user, expires_in, scopes, client_id)


def revoke_refresh_token(jti, exp):
    try:
        blacklist.blacklist_token(jti, exp)
    except errors.JWTError as e:
        return (e.message, e.code)
    return ('Successfully deleted!', 202)
