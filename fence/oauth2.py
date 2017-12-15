# pylint: disable=protected-access,unused-argument
"""
Define the ``OAuth2Provider`` used by fence and set its related handler
functions for storing and loading ``Grant`` models and loading ``Client``
models.

In the implementation here with JWT, a grant is a thin wrapper around the
client from which an authorization request was issued, and the code being used
for a specific request; additionally, the grant is able to throw itself away
when the procedure is completed or after a short timeout.

The token setter and getter functions for the OAuth provider do pretty much
nothing, since the JWTs contain all the necessary information and are
stateless.
"""

from __future__ import print_function

from datetime import datetime, timedelta
import json
import uuid

from cdispyutils.log import get_logger
import flask
from flask_oauthlib.provider import OAuth2Provider
from flask_sqlalchemy_session import current_session
import jwt
import oauthlib

from fence import blacklist
from fence import models
from fence.auth import get_current_user
from fence.jwt_validator import JWTValidator
from fence.utils import hash_secret


log = get_logger('fence')

oauth = OAuth2Provider()


@oauth.grantgetter
def load_grant(client_id, code):
    """
    Load in a ``Grant`` model from the table for this client and authorization
    code.
    """
    return (
        current_session
        .query(models.Grant)
        .filter_by(client_id=client_id, code=code)
        .first()
    )


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    """
    Save a ``Grant`` to the table originating from the given request, using the
    client id and code provided to initialize the grant as well as the scopes
    from the request. The grant expires after a short timeout.
    """
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = models.Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=get_current_user(),
        expires=expires
    )
    current_session.add(grant)
    current_session.commit()
    return grant


@oauth.clientgetter
def load_client(client_id):
    """
    Look up a ``Client`` in the database.
    """
    return (
        current_session
        .query(models.Client)
        .filter_by(client_id=client_id)
        .first()
    )


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    """
    Tokens are signed JWTs, so there is no need for fence to save the tokens;
    just pass.
    """
    pass


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    """
    Tokens aren't saved by fence (see ``save_token`` above), so just return the
    token itself.
    """
    return access_token or refresh_token


# Redefine the request validator used by the OAuth provider, using the
# JWTValidator which redefines bearer and refresh token validation to use JWT.
oauth._validator = JWTValidator(
    clientgetter=oauth._clientgetter,
    tokengetter=oauth._tokengetter,
    grantgetter=oauth._grantgetter,
    usergetter=None,
    tokensetter=oauth._tokensetter,
    grantsetter=oauth._grantsetter,
)


def signed_access_token_generator(kid, private_key, **kwargs):
    """
    Return a function which takes in an oauthlib request and generates a signed
    JWT access token. This function should be assigned as the access token
    generator for the flask app:

    .. code-block:: python

        app.config['OAUTH2_PROVIDER_TOKEN_GENERATOR'] = (
            signed_access_token_generator(private_key)
        )

    (This is the reason for the particular return type of this function.)

    Args:
        kid (str): key ID, name of the keypair used to sign/verify the token
        private_key (str): the private key used to sign the token

    Return:
        Callable[[oauthlib.common.Request], str]
    """
    def generate_signed_access_token_from_request(request):
        """
        Args:
            request (oauthlib.common.Request)

        Return:
            str: encoded JWT signed with ``private_key``
        """
        return generate_signed_access_token(kid, private_key, request)
    return generate_signed_access_token_from_request


def signed_refresh_token_generator(kid, private_key, **kwargs):
    """
    Return a function which takes in an oauthlib request and generates a signed
    JWT refresh token. This function should be assigned as the refresh token
    generator for the flask app:

    .. code-block:: python

        app.config['OAUTH2_PROVIDER_REFRESH_TOKEN_GENERATOR'] = (
            signed_refresh_token_generator(private_key)
        )

    (This is the reason for the particular return type of this function.)

    Args:
        kid (str): key ID, name of the keypair used to sign/verify the token
        private_key (str): the private key used to sign the token

    Return:
        Callable[[oauthlib.common.Request], str]
    """
    def generate_signed_refresh_token_from_request(request):
        """
        Args:
            request (oauthlib.common.Request)

        Return:
            str: encoded JWT signed with ``private_key``
        """
        return generate_signed_refresh_token(kid, private_key, request)
    return generate_signed_refresh_token_from_request


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


def generate_signed_refresh_token(kid, private_key, request):
    """
    Generate a JWT refresh token from the given request, and output a UTF-8
    string of the encoded JWT signed with the private key.

    Args:
        private_key (str): RSA private key to sign and encode the JWT with
        request (oauthlib.common.Request): token request to handle

    Return:
        str: encoded JWT refresh token signed with ``private_key``
    """
    grant = load_grant(request.body.get('client_id'), request.body.get('code'))
    user = grant.user
    headers = {'kid': kid}
    iat, exp = issued_and_expiration_times(request.expires_in)
    claims = {
        'aud': ['refresh'],
        'sub': str(user.id),
        'iss': flask.current_app.config.get('HOST_NAME'),
        'iat': iat,
        'exp': exp,
        'jti': str(uuid.uuid4()),
        'access_aud': request.scopes,
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


def generate_signed_access_token(kid, private_key, request):
    """
    Generate a JWT refresh token from the given request, and output a UTF-8
    string of the encoded JWT signed with the private key.

    Args:
        private_key (str): RSA private key to sign and encode the JWT with
        request (oauthlib.common.Request): token request to handle

    Return:
        str: encoded JWT access token signed with ``private_key``
    """
    grant = load_grant(request.body.get('client_id'), request.body.get('code'))
    user = grant.user
    headers = {'kid': kid}
    iat, exp = issued_and_expiration_times(request.expires_in)
    claims = {
        'aud': request.scopes + ['access'],
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


def init_oauth(app):
    """
    Initialize the OAuth provider on the given app, with
    ``signed_access_token_generator`` and ``signed_refresh_token_generator``
    (using the key ID and private first keypair) as the token generating
    functions for the provider.
    """
    keypair = app.keypairs[0]
    app.config['OAUTH2_PROVIDER_REFRESH_TOKEN_GENERATOR'] = (
        signed_refresh_token_generator(keypair.kid, keypair.private_key)
    )
    app.config['OAUTH2_PROVIDER_TOKEN_GENERATOR'] = (
        signed_access_token_generator(keypair.kid, keypair.private_key)
    )
    app.config['OAUTH2_PROVIDER_TOKEN_EXPIRES_IN'] = 3600
    oauth.init_app(app)


blueprint = flask.Blueprint('oauth2', __name__)


@blueprint.route('/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
def authorize(*args, **kwargs):
    """
    Handle the first step in the OAuth procedure.

    If the method is ``GET``, render a confirmation page. For ``POST``, check
    that the value of ``confirm`` in the form data is exactly ``"yes"``.
    """
    if flask.request.method == 'GET':
        client_id = kwargs.get('client_id')
        client = (
            current_session
            .query(models.Client)
            .filter_by(client_id=client_id)
            .first()
        )
        if client.auto_approve:
            return True
        kwargs['client'] = client
        return flask.render_template('oauthorize.html', **kwargs)

    confirm = flask.request.form.get('confirm', 'no')
    return confirm == 'yes'


@blueprint.route('/token', methods=['POST'])
@hash_secret
@oauth.token_handler
def get_access_token(*args, **kwargs):
    """
    Handle exchanging code for and refreshing the access token.

    The operation here is handled entirely by the ``oauth.token_handler``
    decorator, so this function only needs to pass.

    See the OpenAPI documentation for detailed specification, and the OAuth2
    tests for examples of some operation and correct behavior.
    """
    pass


@blueprint.route('/revoke', methods=['POST'])
def revoke_token():
    """
    Revoke a refresh token.

    If the operation is successful, return an empty response with a 204 status
    code. Otherwise, return error message in JSON with a 400 code.

    Return:
        Tuple[str, int]: JSON response and status code
    """
    # Try to get token from form data.
    try:
        encoded_token = flask.request.form['token']
    except KeyError:
        return (flask.jsonify({'errors': 'no token provided'}), 400)

    # Try to blacklist the token; see possible exceptions raised in
    # ``blacklist_encoded_token``.
    try:
        blacklist.blacklist_encoded_token(encoded_token)
    except jwt.InvalidTokenError as e:
        return (flask.jsonify({'errors': 'invalid token: {}'.format(e)}), 400)
    except KeyError as e:
        msg = 'token missing claim: {}'.format(str(e))
        return (flask.jsonify({'errors': msg}), 400)
    except ValueError as e:
        return (flask.jsonify({'errors': str(e)}), 400)

    return ('', 204)


@blueprint.route('/errors', methods=['GET'])
def display_error():
    """
    Define the errors endpoint for the OAuth provider.
    """
    return flask.jsonify(flask.request.args)
