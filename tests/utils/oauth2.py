import base64
import urlparse

from authlib.common.encoding import to_bytes, to_unicode
from authlib.common.urls import url_decode

import fence.utils


def make_query_string(params):
    if not params:
        return ''
    params_str = '&'.join(
        '{}={}'.format(key, value.replace(' ', '%20'))
        for key, value in params.iteritems()
    )
    return '?' + params_str


def path_for_authorize(params=None):
    return '/oauth2/authorize' + make_query_string(params)


def get_authorize(client, oauth_client, data=None, confirm=None):
    """
    Args:
        client: client fixture
        oauth_client: oauth client fixture
        scope: scope to request

    Return:
        pytest_flask.plugin.JSONResponse: the response from /oauth2/authorize
    """
    data = data or {}
    default_data = {
        'client_id': oauth_client.client_id,
        'redirect_uri': oauth_client.url,
        'response_type': 'code',
        'scope': 'openid user',
        'state': fence.utils.random_str(10)
    }
    default_data.update(data)
    data = default_data
    if confirm is not None:
        if confirm:
            data['confirm'] = 'yes'
        else:
            data['confirm'] = 'no'

    if isinstance(data['scope'], list):
        data['scope'] = ' '.join(data['scope'])
    path = path_for_authorize(data)
    return client.get(path)


def post_authorize(client, oauth_client, data=None, confirm=None):
    """
    Args:
        client: client fixture
        oauth_client: oauth client fixture
        data: form data to include in request
        confirm: if set to ``True`` will include ``confirm=yes`` in the data

    Return:
        pytest_flask.plugin.JSONResponse: the response from /oauth2/authorize
    """
    headers = create_basic_header_for_client(oauth_client)
    data = data or {}
    default_data = {
        'client_id': oauth_client.client_id,
        'redirect_uri': oauth_client.url,
        'response_type': 'code',
        'scope': 'openid user',
        'state': fence.utils.random_str(10),
    }
    default_data.update(data)
    data = default_data
    if confirm is not None:
        if confirm:
            data['confirm'] = 'yes'
        else:
            data['confirm'] = 'no'
    if isinstance(data['scope'], list):
        data['scope'] = ' '.join(data['scope'])
    return client.post(path_for_authorize(), headers=headers, data=data)


def code_from_authorize_response(response):
    """
    Get the code out from a response from ``/oauth2/authorize``.

    Args:
        response (pytest_flask.plugin.JSONResponse): response to get code from

    Return:
        str: the code
    """
    location = response.headers['Location']
    try:
        return dict(url_decode(urlparse.urlparse(location).query))['code']
    except KeyError:
        raise ValueError(
            'response did not contain a code; got headers:\n{}'
            .format(response.headers)
        )


def get_access_code(client, oauth_client, data=None):
    """
    Do all steps to get an authorization code from ``/oauth2/authorize``

    Args:
        client: client fixture
        oauth_client: oauth client fixture
        scope: scope to request

    Return:
        str: the authorization code
    """
    return code_from_authorize_response(post_authorize(
        client, oauth_client, data=data, confirm=True
    ))


def post_token(client, oauth_client, code):
    """
    Return the response from ``POST /oauth2/token``.

    Args:
        client: client fixture
        oauth_client: oauth client fixture
        code (str): code obtained from oauth to exchange for token

    Return:
        pytest_flask.plugin.JSONResponse: the response
    """
    headers = create_basic_header_for_client(oauth_client)
    data = {
        'client_id': oauth_client.client_id,
        'client_secret': oauth_client.client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': oauth_client.url,
    }
    return client.post('/oauth2/token', headers=headers, data=data)


def post_token_refresh(client, oauth_client, refresh_token):
    headers = create_basic_header_for_client(oauth_client)
    data = {
        'client_id': oauth_client.client_id,
        'client_secret': oauth_client.client_secret,
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
    }
    return client.post('/oauth2/token', headers=headers, data=data)


def get_token_response(
        client, oauth_client, scope=None, code_request_data=None):
    """
    Args:
        client: client fixture
        oauth_client: oauth client fixture

    Return:
        pytest_flask.plugin.JSONResponse: the response from ``/oauth2/token``
    """
    code = get_access_code(client, oauth_client, data=code_request_data)
    return post_token(client, oauth_client, code)


def create_basic_header(username, password):
    """
    Create an authorization header from the username and password according to
    RFC 2617 (https://tools.ietf.org/html/rfc2617).

    Use this to send client credentials in the authorization header.
    """
    text = '{}:{}'.format(username, password)
    auth = to_unicode(base64.b64encode(to_bytes(text)))
    return {'Authorization': 'Basic ' + auth}


def create_basic_header_for_client(oauth_client):
    """
    Wrap ``create_basic_header`` to make a header for the client.
    """
    return create_basic_header(
        oauth_client.client_id, oauth_client.client_secret
    )


def check_token_response(token_response):
    """
    Do some basic checks on a token response.
    """
    assert 'id_token' in token_response.json, token_response.json
    assert 'access_token' in token_response.json, token_response.json
    assert 'refresh_token' in token_response.json, token_response.json
