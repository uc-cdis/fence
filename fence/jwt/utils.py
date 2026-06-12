from cdislogging import get_logger
import flask

from fence.config import config
from fence.errors import Unauthorized


logger = get_logger(__name__)


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
        raise Unauthorized("unexpected Authorization header format (expected `Bearer`)")
    try:
        jwt = header.split(" ")[1]
    except IndexError:
        msg = "authorization header missing token"
        logger.debug(f"{msg}. Received header: {header}")
        logger.error(f"{msg}.")
        raise Unauthorized(msg)
    return jwt


def is_task_token(pur, aud):
    if pur != "access":
        return False
    aud = [e for e in aud if e != config["DEFAULT_TOKEN_AUDIENCE"]]
    return aud and all(aud in config["ALLOWED_TASK_TOKEN_TYPES"] for aud in aud)
