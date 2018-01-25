from datetime import datetime

from flask import current_app as cur_app
from ...jwt import token, errors, blacklist
from flask import jsonify

from fence.data_model.models import UserRefreshToken


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


def create_access_token(user, keypair, refresh_token, expires_in, client_id):
    try:
        decoded_jwt = token.validate_refresh_token(refresh_token)
        scopes = decoded_jwt['access_aud']
    except Exception as e:
        return jsonify({'errors': e.message})
    return token.generate_signed_access_token(keypair.kid, keypair.private_key, user, expires_in, scopes, client_id)


def revoke_refresh_token(jti, exp):
    try:
        blacklist.blacklist_token(jti, exp)
    except errors.JWTError as e:
        return (e.message, e.code)
    return ('Successfully deleted!', 202)
