import flask
from flask import current_app

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
    user = query_for_user(session=current_app.scoped_session(), username=username)
    if not user:
        # edge case where the session has a user but the user doesn't exist in the DB
        # (for example, the user was deleted from the DB while logged in)
        raise Unauthorized("User not logged in")
    return user
