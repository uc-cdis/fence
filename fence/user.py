import flask
from flask_sqlalchemy_session import current_session

from fence.errors import Unauthorized
from fence.models import User


def get_current_user():
    username = flask.session.get('username')
    mock_auth_token = flask.current_app.config.get('MOCK_AUTH')
    if mock_auth_token:
        username = mock_auth_token['context']['user']['name']
    if not username:
        raise Unauthorized("User not logged in")
    return current_session.query(User).filter_by(username=username).first()
