from fence.errors import APIError


class ArboristError(APIError):
    """Generic exception related to problems with arborist."""

    pass


class ArboristUnhealthyError(ArboristError):  # pragma: no cover
    """Exception raised to signify the arborist service is unresponsive."""

    def __init__(self):
        super(ArboristUnhealthyError, self).__init__()
        self.message = "could not reach arborist service"
        self.code = 500
        self.json = {"error": self.message, "code": self.code}
