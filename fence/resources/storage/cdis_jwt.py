import flask
import time

from fence.auth import get_user_from_claims
from fence.config import config
from fence.errors import Unauthorized, UserError
from fence.jwt import token
from fence.jwt.errors import JWTError
from fence.jwt.validate import validate_jwt
from fence.models import UserRefreshToken


def create_access_token(user, keypair, api_key, expires_in, scopes):
    try:
        claims = validate_jwt(api_key, scope=scopes, purpose="api_key")
        if not set(claims["scope"]).issuperset(scopes):
            raise JWTError("cannot issue access token with scope beyond refresh token")
    except Exception as e:
        return flask.jsonify({"errors": str(e)})
    return token.generate_signed_access_token(
        keypair.kid, keypair.private_key, expires_in, scopes, user=user
    ).token


def create_api_key(user_id, keypair, expires_in, scopes, client_id):
    jwt_result = token.generate_api_key(
        keypair.kid, keypair.private_key, user_id, expires_in, scopes, client_id
    )
    with flask.current_app.db.session as session:
        session.add(
            UserRefreshToken(
                jti=jwt_result.claims["jti"],
                userid=user_id,
                expires=jwt_result.claims["exp"],
            )
        )
        session.commit()
    return jwt_result.token, jwt_result.claims


def create_session_token(keypair, expires_in, context=None):
    return token.generate_signed_session_token(
        keypair.kid, keypair.private_key, expires_in, context
    ).token


def create_user_access_token(keypair, api_key, expires_in, task_token_type):
    """
    create access token given a user's api key
    Args:
        keypair: RSA keypair for signing jwt
        api_key: user created jwt token, the azp should match with user.id
        expires_in: expiration time in seconds
        task_token_type: type of task token to create, if any, otherwise None
    Return:
        access token
    """
    try:
        claims = validate_jwt(api_key, scope={"fence"}, purpose="api_key")
        scopes = claims["scope"]

        user = get_user_from_claims(claims)
    except Exception as e:
        raise Unauthorized(str(e))

    if claims.get("exp", 0) < time.time() + expires_in:
        raise UserError(
            "Cannot issue an access token that would expire after the provided API key does. Please obtain a new API key and try again"
        )

    return token.generate_signed_access_token(
        keypair.kid,
        keypair.private_key,
        expires_in,
        scopes,
        audience=task_token_type,
        user=user,
        task_token_type=task_token_type,
    ).token
