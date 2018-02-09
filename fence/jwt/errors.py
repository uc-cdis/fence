from fence.errors import AuthError


class JWTError(AuthError):

    def __init__(self, message, code=401):
        self.message = str(message)
        self.code = code


class JWTPurposeError(JWTError):
    pass
