import flask
from flask_sqlalchemy_session import current_session

from fence.errors import Unauthorized
from fence.models import query_for_user
from fence.config import config


def get_current_user(flask_session=None):
    flask_session = flask_session or flask.session
    username = flask_session.get("username")
    if config.get("MOCK_AUTH", False) is True:
        username = "test"
    if not username:
        raise Unauthorized("User not logged in")
    return query_for_user(session=current_session, username=username)
