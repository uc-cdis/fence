from ...jwt import token, errors
from flask import jsonify


def create_refresh_token(user, keypair, expires_in, scopes, client_id):
    return token.generate_signed_refresh_token(keypair.kid, keypair.private_key, user, expires_in, scopes, client_id)


def create_session_token(keypair, expires_in, username=None,
                         session_started=None, provider=None, redirect=None):
    return token.generate_signed_session_token(keypair.kid, keypair.private_key,
                                               expires_in, username,
                                               session_started, provider, redirect)


def create_access_token(user, keypair, refresh_token, expires_in, scopes, client_id):
    try:
        token.validate_refresh_token(refresh_token)
    except Exception as e:
        return jsonify({'errors': e.message})
    return token.generate_signed_access_token(keypair.kid, keypair.private_key, user, expires_in, scopes, client_id)


def revoke_refresh_token(encoded_token):
    try:
        token.revoke_token(encoded_token)
    except errors.JWTError as e:
        return (e.message, e.code)
    return ('', 204)
