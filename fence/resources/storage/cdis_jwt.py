from datetime import datetime

import jwt
import flask

from fence.jwt import token
from fence.jwt.errors import JWTError
from fence.models import UserRefreshToken


def create_id_token(
        user, keypair, expires_in, client_id, audiences=None,
        auth_time=None, max_age=None, nonce=None):
    try:
        return token.generate_signed_id_token(
            keypair.kid, keypair.private_key, user, expires_in, client_id,
            audiences=audiences, auth_time=auth_time, max_age=max_age,
            nonce=nonce
        )
    except Exception as e:
        return flask.jsonify({'errors': e.message})


def create_refresh_token(user, keypair, expires_in, scopes, client_id):
    return_token = token.generate_signed_refresh_token(
        keypair.kid, keypair.private_key, user, expires_in, scopes, client_id
    )
    payload = jwt.decode(
        return_token, keypair.public_key, audience='refresh',
        algorithms=['RS256']
    )
    jti = payload['jti']
    # expires = datetime.fromtimestamp(payload['exp']).isoformat()
    expires = datetime.fromtimestamp(payload['exp'])
    with flask.current_app.db.session as session:
        session.add(UserRefreshToken(jti=jti, userid=user.id, expires=expires))
        session.commit()
    return return_token


def create_access_token(
        user, keypair, refresh_token, expires_in, scopes, client_id):
    try:
        token.validate_refresh_token(refresh_token)
    except Exception as e:
        return flask.jsonify({'errors': e.message})
    return token.generate_signed_access_token(
        keypair.kid, keypair.private_key, user, expires_in, scopes, client_id
    )


def revoke_refresh_token(encoded_token):
    try:
        token.revoke_token(encoded_token)
    except JWTError as e:
        return (e.message, e.code)
    return ('', 204)
