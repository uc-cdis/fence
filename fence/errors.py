from cdiserrors import APIError


class AuthError(APIError):
    pass


class UserError(APIError):
    def __init__(self, message):
        self.message = str(message)
        self.code = 400


class BlacklistingError(APIError):
    def __init__(self, message):
        self.message = str(message)
        self.code = 400


class InternalError(APIError):
    def __init__(self, message):
        super(InternalError, self).__init__(message)
        self.message = str(message)
        self.code = 500


class Unauthorized(APIError):

    def __init__(self, message):
        self.message = str(message)
        self.code = 401


class NotFound(APIError):
    def __init__(self, message):
        self.message = str(message)
        self.code = 404


class NotSupported(APIError):
    def __init__(self, message):
        self.message = str(message)
        self.code = 400


class UnavailableError(APIError):
    def __init__(self, message):
        self.message = str(message)
        self.code = 503


class NoSuchUserError(APIError):
    """
    Error for when a user is authenticated by an upstream identity provider,
    but the user has not been provisioned in the Fence database and Fence
    is not configured to insert on login.
    """
    def __init__(self, message, redirect):
        self.message = str(message)
        self.redirect = redirect
        self.code = 401
