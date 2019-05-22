def test_default_scope(encoded_creds_jwt, oauth_test_client):
    """
    Test the very basic requirement that including the ``ui_locales`` parameter
    does not cause any errors.
    """
    data = {}
    response = oauth_test_client.authorize(data=data, method="GET", do_asserts=False)
    assert response.response.status_code == 200


def test_scope_separator_in_query_as_plus(encoded_creds_jwt, oauth_test_client):
    """
    Test the very basic requirement that including the ``ui_locales`` parameter
    does not cause any errors.
    """
    data = {"scope": "openid+user"}
    response = oauth_test_client.authorize(
        data=data, method="GET", do_asserts=False, urlencode=False
    )
    assert response.response.status_code == 200


def test_scope_separator_in_query_percent_encoded(encoded_creds_jwt, oauth_test_client):
    """
    Test the very basic requirement that including the ``ui_locales`` parameter
    does not cause any errors.
    """
    data = {"scope": "openid%20user"}
    response = oauth_test_client.authorize(
        data=data, method="GET", do_asserts=False, urlencode=False
    )
    assert response.response.status_code == 200
