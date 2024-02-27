class RequestError(Exception):
    def __init__(self, message, code):
        self.message = message
        self.code = code


class NotFoundError(RequestError):
    def __init__(self, message):
        super().__init__(message, 404)


class ClientSideError(RequestError):
    def __init__(self, message):
        super().__init__(message, 400)
