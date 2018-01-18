from fence.errors import AuthError


class OAuth2Error(AuthError):
    """
    Base class for errors from the OAuth2 specification.
    """
    pass


class InvalidRequestError(OAuth2Error):
    """
    The request is missing a required parameter, includes an unsupported
    parameter value (other than grant type), repeats a parameter, includes
    multiple credentials, utilizes more than one mechanism for authenticating
    the client, or is otherwise malformed.
    """

    def __init__(self, message='', error_uri=None):
        super(InvalidRequestError, self).__init__(message, error_uri)
        self.error_code = 'invalid_request'


class InvalidClientError(OAuth2Error):
    """
    Client authentication failed (e.g., unknown client, no client
    authentication included, or unsupported authentication method).  The
    authorization server MAY return an HTTP 401 (Unauthorized) status code to
    indicate which HTTP authentication schemes are supported.  If the client
    attempted to authenticate via the "Authorization" request header field, the
    authorization server MUST respond with an HTTP 401 (Unauthorized) status
    code and include the "WWW-Authenticate" response header field matching the
    authentication scheme used by the client.
    """

    def __init__(self, message='', error_uri=None):
        super(InvalidClientError, self).__init__(message, error_uri)
        self.error_code = 'invalid_client'


class InvalidGrantError(OAuth2Error):
    """
    Client authentication failed (e.g., unknown client, no client
    authentication included, or unsupported authentication method).  The
    authorization server MAY return an HTTP 401 (Unauthorized) status code to
    indicate which HTTP authentication schemes are supported.  If the client
    attempted to authenticate via the "Authorization" request header field, the
    authorization server MUST respond with an HTTP 401 (Unauthorized) status
    code and include the "WWW-Authenticate" response header field matching the
    authentication scheme used by the client.
    """

    def __init__(self, message='', error_uri=None):
        super(InvalidGrantError, self).__init__(message, error_uri)
        self.error_code = 'invalid_grant'


class UnauthorizedClientError(OAuth2Error):
    """
    The authenticated client is not authorized to use this authorization grant
    type.
    """

    def __init__(self, message='', error_uri=None):
        super(UnauthorizedClientError, self).__init__(message, error_uri)
        self.error_code = 'unauthorized_client'


class UnsupportedGrantTypeError(OAuth2Error):
    """
    The authorization grant type is not supported by the authorization server.
    """

    def __init__(self, message='', error_uri=None):
        super(UnsupportedGrantTypeError, self).__init__(message, error_uri)
        self.error_code = 'unsupported_grant_type'


class InvalidScopeError(OAuth2Error):
    """
    The requested scope is invalid, unknown, malformed, or exceeds the scope
    granted by the resource owner.
    """

    def __init__(self, message='', error_uri=None):
        super(InvalidScopeError, self).__init__(message, error_uri)
        self.error_code = 'invalid_scope'
