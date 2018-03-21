from addict import Dict
import flask
from flask_sqlalchemy_session import current_session
from werkzeug.local import LocalProxy

from fence.auth import current_token
from fence.models import User


def _get_current_user():
    """
    Get the username from the session, an available token, or the mock auth
    token, and query for the ``User`` model having that username. Put all the
    info in a dict to prevent sqlalchemy session nightmares, and return that.

    Return:
        addict.Dict: attribute dictionary of everything on the ``User`` model
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
    user = current_session.query(User).filter_by(username=username).first()
    if not user:
        return None
    return Dict(dict(user.__dict__))


def _get_and_set_current_user():
    """
    Try to set the current user, and return it.

    Return:
        fence.models.User
    """
    if not hasattr(flask.g, '_current_user'):
        flask.g._current_user = _get_current_user()
    return flask.g._current_user


current_user = LocalProxy(_get_and_set_current_user)
