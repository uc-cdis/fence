from ...jwt import token, errors
from flask import jsonify


def create_id_token(
        user, keypair, expires_in, scopes, client_id, audiences=None,
        auth_time=None, max_age=None, nonce=None):
    try:
        return token.generate_signed_id_token(
            keypair.kid, keypair.private_key, user, expires_in, scopes, client_id,
            audiences=audiences, auth_time=auth_time, max_age=max_age, nonce=nonce)
    except Exception as e:
        return jsonify({'errors': e.message})


def create_refresh_token(user, keypair, expires_in, scopes):
    return token.generate_signed_refresh_token(keypair.kid, keypair.private_key, user, expires_in, scopes)


def create_access_token(user, keypair, refresh_token, expires_in, scopes):
    try:
        token.validate_refresh_token(refresh_token)
    except Exception as e:
        return jsonify({'errors': e.message})
    return token.generate_signed_access_token(keypair.kid, keypair.private_key, user, expires_in, scopes)


def revoke_refresh_token(encoded_token):
    try:
        token.revoke_token(encoded_token)
    except errors.JWTError as e:
        return (e.message, e.code)
    return ('', 204)
