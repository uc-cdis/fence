import flask

from fence.errors import Unauthorized


def get_jwt_header():
    """
    Get the user's JWT from the Authorization header, or raise Unauthorized on failure.

    Return just the entire JWT as a string, without further validation or processing.
    """
    try:
        header = flask.request.headers["Authorization"]
    except KeyError:
        raise Unauthorized("missing authorization header")
    if not header.lower().startswith("bearer"):
        raise Unauthorized("unexpected Authorization header format (expected `Bearer`")
    try:
        jwt = header.split(" ")[1]
    except IndexError:
        raise Unauthorized("authorization header missing token")
    return jwt
