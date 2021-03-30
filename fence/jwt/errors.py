from fence.errors import AuthError, InternalError


class JWTError(AuthError):
    def __init__(self, message, code=401):
        super(JWTError, self).__init__(message)
        self.message = str(message)
        self.code = code


class JWTPurposeError(JWTError):
    pass


class JWTSizeError(InternalError):
    """
    JWT exceeded 4096 bytes, after which browser may clip cookies.
    See RFC 2109 $6.3.
    """

    def __init__(self, message):
        super(JWTSizeError, self).__init__(message)
        self.message = str(message)
