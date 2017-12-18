class JWTError(Exception):
    def __init__(self, message, code=400):
        self.message = str(message)
        self.code = code
