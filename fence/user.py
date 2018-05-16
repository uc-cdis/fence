import flask
from flask_sqlalchemy_session import current_session
from sqlalchemy import func

from fence.errors import Unauthorized
from fence.models import User


def get_current_user():
    username = flask.session.get('username')
    if flask.current_app.config.get('MOCK_AUTH', False) is True:
        username = 'test'
    if not username:
        raise Unauthorized("User not logged in")
    username = username.lower()
    return current_session.query(User).filter_by(func.lower(username)=username).first()
