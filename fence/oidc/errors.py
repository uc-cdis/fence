from fence.errors import AuthError


class OIDCError(AuthError):
    """
    Base class for errors specified by OIDC.
    """

    status_code = 400
    error_code = "oidc_error"

    def __init__(self, message=""):
        self.message = message

    def __str__(self):
        msg = self.error_code
        if self.message:
            msg += self.message
        return msg


class InvalidClientError(OIDCError):
    """
    The client in an OIDC request has failed to authorize.
    """

    status_code = 401
    error_code = "invalid_client"


class InteractionRequiredError(OIDCError):
    """
    The Authorization Server requires End-User interaction of some form to
    proceed. This error MAY be returned when the prompt parameter value in the
    Authentication Request is none, but the Authentication Request cannot be
    completed without displaying a user interface for End-User interaction.
    """

    error_code = "interaction_required"


class LoginRequiredError(InteractionRequiredError):
    """
    The Authorization Server requires End-User authentication. This error MAY
    be returned when the prompt parameter value in the Authentication Request
    is none, but the Authentication Request cannot be completed without
    displaying a user interface for End-User authentication.
    """

    pass


class AccountSelectionRequiredError(InteractionRequiredError):
    """
    The End-User is REQUIRED to select a session at the Authorization Server.
    The End-User MAY be authenticated at the Authorization Server with
    different associated accounts, but the End-User did not select a session.
    This error MAY be returned when the prompt parameter value in the
    Authentication Request is none, but the Authentication Request cannot be
    completed without displaying a user interface to prompt for a session to
    use.
    """

    pass


class ConsentRequiredError(InteractionRequiredError):
    """
    The Authorization Server requires End-User consent. This error MAY be
    returned when the prompt parameter value in the Authentication Request is
    none, but the Authentication Request cannot be completed without displaying
    a user interface for End-User consent.
    """

    pass


class InvalidRequestUriError(InteractionRequiredError):
    """
    The request_uri in the Authorization Request returns an error or contains
    invalid data.
    """

    pass


class InvalidRequestObjectError(InteractionRequiredError):
    """
    The request parameter contains an invalid Request Object.
    """

    pass


class RequestNotSupportedError(InteractionRequiredError):
    """
    The OP does not support use of the request parameter defined in Section 6.
    """

    pass


class RequestUriNotSupportedError(InteractionRequiredError):
    """
    The OP does not support use of the request_uri parameter defined in Section
    6.
    """

    pass


class RegistrationNotSupportedError(InteractionRequiredError):
    """
    The OP does not support use of the registration parameter defined in
    Section 7.2.1.
    """

    pass
