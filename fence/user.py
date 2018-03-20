import flask
from flask_sqlalchemy_session import current_session
from werkzeug.local import LocalProxy

from fence.auth import current_token
from fence.models import User


def get_current_user():
    """
    Get the username from the session, an available token, or the mock auth
    token, and query for the ``User`` model having that username.

    Return:
        fence.models.User
    """
    username = flask.session.get('username')
    if current_token:
        username = current_token['context']['user']['name']
    else:
        mock_auth_token = flask.current_app.config.get('MOCK_AUTH')
        if mock_auth_token:
            username = mock_auth_token['context']['user']['name']
    if not username:
        return None
    return current_session.query(User).filter_by(username=username).first()
