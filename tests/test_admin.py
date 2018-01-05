from cdispyutils import auth
import flask

from tests import utils


def test_is_admin_positive(client, oauth_client_with_admin, public_key):
    """
    Get a token for an admin user and test that the ``'is_admin'`` entry in the
    token is true.
    """
    response = utils.oauth2.get_token_response(
        client, oauth_client_with_admin
    )
    encoded_access_token = response.json['access_token']
    access_token = auth.validate_jwt(
        encoded_token=encoded_access_token,
        public_key=public_key,
        aud={'access'},
        iss=flask.current_app.config['HOST_NAME'],
    )
    assert 'is_admin' in access_token['context']['user']
    assert access_token['context']['user']['is_admin'] is True


def test_is_admin_negative(client, oauth_client, public_key):
    """
    Go through the token procedure with the default (non-admin) user and test
    that the ``'is_admin'`` entry in the token is false.
    """
    response = utils.oauth2.get_token_response(client, oauth_client)
    encoded_access_token = response.json['access_token']
    access_token = auth.validate_jwt(
        encoded_token=encoded_access_token,
        public_key=public_key,
        aud={'access'},
        iss=flask.current_app.config['HOST_NAME'],
    )
    assert 'is_admin' in access_token['context']['user']
    assert access_token['context']['user']['is_admin'] is False
