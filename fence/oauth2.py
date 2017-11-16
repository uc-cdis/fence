from __future__ import print_function

from datetime import datetime, timedelta
import os
import uuid

from cdispyutils.log import get_logger
import flask
from flask import render_template, jsonify, request
from flask_oauthlib.provider import OAuth2Provider
from flask_sqlalchemy_session import current_session
import jwt
import oauthlib

from . import models
from .auth import get_current_user
from .jwt_validator import JWTValidator
from .utils import hash_secret


log = get_logger('fence')


oauth = OAuth2Provider()


@oauth.grantgetter
def load_grant(client_id, code):
    return (
        current_session
        .query(models.Grant)
        .filter_by(client_id=client_id, code=code)
        .first()
    )


@oauth.clientgetter
def load_client(client_id):
    return (
        current_session
        .query(models.Client)
        .filter_by(client_id=client_id)
        .first()
    )


@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
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


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = current_session.query(models.Token).filter_by(
        client_id=request.client.client_id,
        user_id=request.user.id)
    # make sure that every client has only one token connected to a user
    for t in toks:
        current_session.delete(t)

    expires_in = token.get('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = models.Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    current_session.add(tok)
    current_session.commit()
    return tok


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return (
            current_session
            .query(models.Token)
            .filter_by(access_token=access_token)
            .first()
        )
    elif refresh_token:
        return (
            current_session
            .query(models.Token)
            .filter_by(refresh_token=refresh_token)
            .first()
        )


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


def signed_token_generator(private_key, **kwargs):
    def signed_token_generator(request):
        request.claims = kwargs
        return oauthlib.common.generate_signed_token(private_key, request)
    return signed_token_generator


def generate_signed_token(private_key, request):
    """
    Generate a JWT from the given request, and output a UTF-8 string of the JWT
    encoded using the private key.

    Args:
        private_key (str): RSA private key to sign and encode the JWT with
        request (oauthlib.common.Request): TODO
    """
    now = datetime.datetime.utcnow()
    for p in dir(request):
        log.exception(p, ': ', getattr(request, p))
    # TODO: JWT fields
    TODO = 'TODO'
    claims = {
        'sub': TODO,
        'iss': TODO,
        'iat': now,
        'exp': now + datetime.timedelta(seconds=request.expires_in),
        'jti': str(uuid.uuid4()),
        'aud': TODO,
        'scopes': request.scopes,
        'context': {
            'user': request.user,
        }
    }
    claims.update(request.claims)
    raise RuntimeError('JWT: ' + str(claims))
    token = jwt.encode(claims, private_key, 'RS256')
    token = oauthlib.common.to_unicode(token, 'UTF-8')
    return token


def init_oauth(app):
    parent = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    keys_dir = os.path.join(parent, 'keys')
    public_key_filename = os.path.join(keys_dir, 'jwt_public_key.pem')
    private_key_filename = os.path.join(keys_dir, 'jwt_private_key.pem')
    with open(public_key_filename, 'r') as f:
        app.config['JWT_PUBLIC_KEY'] = f.read()
    with open(private_key_filename, 'r') as f:
        app.config['JWT_PRIVATE_KEY'] = f.read()
    private_key = app.config['JWT_PRIVATE_KEY']

    app.config['OAUTH2_PROVIDER_REFRESH_TOKEN_GENERATOR'] = (
        signed_token_generator(private_key)
    )
    app.config['OAUTH2_PROVIDER_TOKEN_GENERATOR'] = (
        signed_token_generator(private_key)
    )
    app.config['OAUTH2_PROVIDER_TOKEN_EXPIRES_IN'] = 3600
    oauth.init_app(app)


blueprint = flask.Blueprint('oauth2', __name__)


@blueprint.route('/authorize', methods=['GET', 'POST'])
@oauth.authorize_handler
def authorize(*args, **kwargs):
    if request.method == 'GET':
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
        return render_template('oauthorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'


@blueprint.route('/token', methods=['POST'])
@hash_secret
@oauth.token_handler
def access_token(*args, **kwargs):
    """
    Handle exchanging and refreshing the access token.

    The operation here is handled entirely by the ``oauth.token_handler``
    decorator, so this function only needs to pass.
    """
    pass


@blueprint.route('/revoke', methods=['POST'])
@oauth.revoke_handler
def revoke_token():
    """
    Revoke the access given to an application.

    The operation is handled by the ``oauth.revoke_handler`` decorator, so this
    function just passes.
    """
    pass


@blueprint.route('/errors', methods=['GET'])
def display_error():
    return jsonify(request.args)
