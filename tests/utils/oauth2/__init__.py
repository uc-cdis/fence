import base64

from authlib.common.encoding import to_bytes, to_unicode

import fence.utils


def create_basic_header(username, password):
    """
    Create an authorization header from the username and password according to
    RFC 2617 (https://tools.ietf.org/html/rfc2617).

    Use this to send client credentials in the authorization header.
    """
    text = "{}:{}".format(username, password)
    auth = to_unicode(base64.b64encode(to_bytes(text)))
    return {"Authorization": "Basic " + auth}


def create_basic_header_for_client(oauth_client):
    """
    Wrap ``create_basic_header`` to make a header for the client.
    """
    return create_basic_header(oauth_client.client_id, oauth_client.client_secret)
