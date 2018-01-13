from fence.errors import AuthError


class OIDCError(AuthError):
    """
    Base class for errors specified by OIDC.
    """
    pass


class InteractionRequiredError(OIDCError):
    """
    The Authorization Server requires End-User interaction of some form to
    proceed. This error MAY be returned when the prompt parameter value in the
    Authentication Request is none, but the Authentication Request cannot be
    completed without displaying a user interface for End-User interaction.
    """

    def __init__(self, message='', error_uri=None):
        super(InteractionRequiredError, self).__init__(message, error_uri)
        self.error_code = 'interaction_required'


class LoginRequiredError(OIDCError):
    """
    The Authorization Server requires End-User authentication. This error MAY
    be returned when the prompt parameter value in the Authentication Request
    is none, but the Authentication Request cannot be completed without
    displaying a user interface for End-User authentication.
    """

    def __init__(self, message='', error_uri=None):
        super(InteractionRequiredError, self).__init__(message, error_uri)
        self.error_code = 'interaction_required'


class AccountSelectionRequiredError(OIDCError):
    """
    The End-User is REQUIRED to select a session at the Authorization Server.
    The End-User MAY be authenticated at the Authorization Server with
    different associated accounts, but the End-User did not select a session.
    This error MAY be returned when the prompt parameter value in the
    Authentication Request is none, but the Authentication Request cannot be
    completed without displaying a user interface to prompt for a session to
    use.
    """

    def __init__(self, message='', error_uri=None):
        super(InteractionRequiredError, self).__init__(message, error_uri)
        self.error_code = 'interaction_required'


class ConsentRequiredError(OIDCError):
    """
    The Authorization Server requires End-User consent. This error MAY be
    returned when the prompt parameter value in the Authentication Request is
    none, but the Authentication Request cannot be completed without displaying
    a user interface for End-User consent.
    """

    def __init__(self, message='', error_uri=None):
        super(InteractionRequiredError, self).__init__(message, error_uri)
        self.error_code = 'interaction_required'


class InvalidRequestUriError(OIDCError):
    """
    The request_uri in the Authorization Request returns an error or contains
    invalid data.
    """

    def __init__(self, message='', error_uri=None):
        super(InteractionRequiredError, self).__init__(message, error_uri)
        self.error_code = 'interaction_required'


class InvalidRequestObjectError(OIDCError):
    """
    The request parameter contains an invalid Request Object.
    """

    def __init__(self, message='', error_uri=None):
        super(InteractionRequiredError, self).__init__(message, error_uri)
        self.error_code = 'interaction_required'


class RequestNotSupportedError(OIDCError):
    """
    The OP does not support use of the request parameter defined in Section 6.
    """

    def __init__(self, message='', error_uri=None):
        super(InteractionRequiredError, self).__init__(message, error_uri)
        self.error_code = 'interaction_required'


class RequestUriNotSupportedError(OIDCError):
    """
    The OP does not support use of the request_uri parameter defined in Section
    6.
    """

    def __init__(self, message='', error_uri=None):
        super(InteractionRequiredError, self).__init__(message, error_uri)
        self.error_code = 'interaction_required'


class RegistrationNotSupportedError(OIDCError):
    """
    The OP does not support use of the registration parameter defined in
    Section 7.2.1.
    """

    def __init__(self, message='', error_uri=None):
        super(InteractionRequiredError, self).__init__(message, error_uri)
        self.error_code = 'interaction_required'
