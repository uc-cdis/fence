from cdispyutils import auth
import flask
import jwt

from fence.jwt.blacklist import is_blacklisted
from fence.jwt.errors import JWTError, JWTPurposeError


def validate_purpose(claims, pur):
    """
    Check that the claims from a JWT have the expected purpose ``pur``

    Args:
        claims (dict): claims from token
        pur (str): expected purpose

    Return:
        None

    Raises:
        JWTPurposeError:
            if the claims do not contain a purpose claim or if it doesn't match
            the expected value
    """
    if 'pur' not in claims:
        raise JWTPurposeError('claims missing `pur` claim')
    if claims['pur'] != pur:
        raise JWTPurposeError(
            'claims have incorrect purpose: expected {}, got {}'
            .format(pur, claims['pur'])
        )


def validate_jwt(encoded_token, aud, purpose=None, public_key=None):
    aud = set(aud)
    iss = flask.current_app.config['HOST_NAME']
    token_headers = jwt.get_unverified_header(encoded_token)
    public_key = auth.get_public_key_for_kid(
        token_headers.get('kid'), attempt_refresh=False
    )
    try:
        claims = auth.validate_jwt(encoded_token, public_key, aud, iss)
    except auth.errors.JWTValidationError as e:
        raise JWTError(str(e))
    if purpose:
        validate_purpose(claims, purpose)
    if 'pur' not in claims:
        raise JWTError(
            'token {} missing purpose (`pur`) claim'
            .format(claims['jti'])
        )
    if claims['pur'] == 'refresh' and is_blacklisted(claims['jti']):
        raise JWTError('token is blacklisted')
    return claims
