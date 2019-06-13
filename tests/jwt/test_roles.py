import pytest
import random
import string
import jwt

from tests.utils import iat_and_exp

from fence.jwt.token import generate_signed_access_token


def test_roles_in_access_token(app, rsa_private_key, test_user_a):
    """
    Test that generate_signed_access_token returns roles and user_id.
    """
    _, exp = iat_and_exp()
    test_user_a.project_access["program-project"] =  ["read-storage", "read", "create", "upload", "update", "delete"]
    jwt_result = generate_signed_access_token(
        "test", rsa_private_key, test_user_a, exp, ["openid", "user"]
    )
    token = jwt.decode(jwt_result.token, verify=False)
    assert 'roles' in token, 'should have a top level "roles" key'
    assert len(token['roles']) > 0, 'should have a roles'
    expected_roles = ["program-project/read-storage", "program-project/read", "program-project/create", "program-project/upload", "program-project/update", "program-project/delete"]
    assert token['roles'] == expected_roles, 'should match expected roles'
    assert 'user_name' in token, 'should have a top level "user_name" key'
