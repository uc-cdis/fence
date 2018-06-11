from collections import OrderedDict
import os

from addict import Dict
from authutils.oauth2.client import OAuthClient
import bcrypt
import flask
import pytest

from fence import models
from fence import app_init
from fence.jwt.keys import Keypair
import fence.blueprints.login

from tests import test_settings


@pytest.fixture(scope='function')
def fence_oauth_client_url():
    return 'http://fence-test-client.net/oauth'


@pytest.fixture(scope='function')
def fence_oauth_client(app, db_session, oauth_user, fence_oauth_client_url):
    """
    Register an OAuth client for a new fence instance to use as an oauth client
    of another fence instance.
    """
    client_id = 'fence_instance'
    client_secret = fence.utils.random_str(50)
    hashed_secret = bcrypt.hashpw(client_secret, bcrypt.gensalt())
    test_user = (
        db_session
        .query(models.User)
        .filter_by(id=oauth_user.user_id)
        .first()
    )
    db_session.add(models.Client(
        client_id=client_id, client_secret=hashed_secret, user=test_user,
        allowed_scopes=['openid', 'user'],
        _redirect_uris=fence_oauth_client_url, description='',
        is_confidential=True, name='fence_oauth_client'
    ))
    db_session.commit()
    return Dict(
        client_id=client_id, client_secret=client_secret,
        url=fence_oauth_client_url
    )


@pytest.fixture(scope='function')
def fence_client_app(
        app, fence_oauth_client, fence_oauth_client_url, db_session,
        kid_2, rsa_private_key_2, rsa_public_key_2):
    """
    A Flask application fixture which acts as a client of the original ``app``
    in a multi-tenant configuration.
    """
    root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    client_app = flask.Flask('client_app')
    app_init(client_app, test_settings, root_dir=root_dir)

    client_app.keypairs.append(Keypair(
        kid=kid_2, public_key=rsa_public_key_2,
        private_key=rsa_private_key_2
    ))

    client_app.jwt_public_keys['/'] = OrderedDict([
        (kid_2, rsa_public_key_2)
    ])

    client_app.config['BASE_URL'] = '/'
    client_app.config['MOCK_AUTH'] = False
    client_app.config['DEFAULT_LOGIN_URL'] = '/login/fence'
    client_app.db.Session = lambda: db_session
    client_app.config['OPENID_CONNECT'] = {
        'fence': {
            'client_id': fence_oauth_client.client_id,
            'client_secret': fence_oauth_client.client_secret,
            'api_base_url': 'http://localhost:50000',
            'authorize_url': 'http://localhost:50000/oauth2/authorize',
            'access_token_url': 'http://localhost:50000/oauth2/token',
            'refresh_token_url': 'http://localhost:50000/oauth2/token',
            'client_kwargs': {
                'scope': 'openid user',
                'redirect_uri': fence_oauth_client_url,
            }
        }
    }
    client_app.fence_client = OAuthClient(
        **client_app.config['OPENID_CONNECT']['fence']
    )
    return client_app


@pytest.fixture(scope='session')
def example_keys_response(kid, rsa_public_key):
    """
    Return an example response JSON returned from the ``/jwt/keys`` endpoint in
    fence.
    """
    return {
        'keys': [
            [kid, rsa_public_key],
        ]
    }
