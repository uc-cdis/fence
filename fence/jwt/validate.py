from cdispyutils import auth
import flask
import jwt


def validate_jwt(encoded_token, aud, public_key=None):
    aud = set(aud)
    iss = flask.current_app.config['HOST_NAME']
    token_headers = jwt.get_unverified_header(encoded_token)
    public_key = auth.get_public_key_for_kid(
        token_headers.get('kid'), attempt_refresh=False
    )
    return auth.validate_jwt(encoded_token, public_key, aud, iss)


def validate_refresh_token(refresh_token, public_key=None):
    return validate_jwt(refresh_token, {'refresh'}, public_key=public_key)
