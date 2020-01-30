import flask

from fence.auth import get_user_from_claims
from fence.errors import Unauthorized
from fence.jwt import token
from fence.jwt.errors import JWTError
from fence.jwt.validate import validate_jwt
from fence.models import UserRefreshToken


def create_access_token(user, keypair, api_key, expires_in, scopes):
    try:
        claims = validate_jwt(api_key, aud=scopes, purpose="api_key")
        if not set(claims["aud"]).issuperset(scopes):
            raise JWTError("cannot issue access token with scope beyond refresh token")
    except Exception as e:
        return flask.jsonify({"errors": str(e)})
    return token.generate_signed_access_token(
        keypair.kid, keypair.private_key, user, expires_in, scopes
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
        claims = validate_jwt(api_key, aud={"fence"}, purpose="api_key")
        scopes = claims["aud"]
        user = get_user_from_claims(claims)
    except Exception as e:
        raise Unauthorized(str(e))
    return token.generate_signed_access_token(
        keypair.kid, keypair.private_key, user, expires_in, scopes
    ).token
