
from fence.jwt.validate import validate_jwt
from fence.jwt.validate import validate_refresh_token
from fence.utils import random_str

from tests.utils import oauth2


def test_default_values(client, oauth_client):
    """
    """
    nonce = random_str(10)
    data = {
        'client_id': oauth_client.client_id,
        'redirect_uri': oauth_client.url,
        'response_type': 'code',
        'scope': 'openid user',
        'state': random_str(10),
        'confirm': 'yes',
        'nonce': nonce,
    }
    token_response = oauth2.get_token_response(
        client, oauth_client, code_request_data=data).json
    id_token = validate_jwt(token_response['id_token'], {'openid'})
    assert nonce == id_token['nonce']
