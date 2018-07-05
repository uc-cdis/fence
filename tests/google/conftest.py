from addict import Dict
import jwt
import pytest

from tests import utils


@pytest.fixture(scope='function')
def encoded_jwt_service_accounts_access(
        kid, rsa_private_key, user_client, oauth_client):
    """
    Return a JWT and user_id for a new user containing the claims and
    encoded with the private key.

    Args:
        claims (dict): fixture
        rsa_private_key (str): fixture

    Return:
        str: JWT containing claims encoded with private key
    """
    headers = {'kid': kid}
    return Dict(
        jwt=jwt.encode(
            utils.authorized_service_account_management_claims(
                user_client['username'], user_client['user_id'],
                oauth_client['client_id']),
            key=rsa_private_key,
            headers=headers,
            algorithm='RS256',
        ),
        user_id=user_client['user_id'],
        client_id=oauth_client['client_id']
    )
