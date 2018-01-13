from fence.errors import AuthError


class JWTError(AuthError):
    def __init__(self, message, code=400):
        self.message = str(message)
        self.code = code
