"""
NOTE: this module used to provide the ``get_current_user`` function to query
for and return a User model. This function is deprecated. Instead, use the
``current_user`` proxy, which is a request-local reference to a dictionary
storing all of the information looked up from the first User lookup. If you
really need specifically a ``fence.models.User`` object for the current user,
do this:

    _get_user(_get_current_username())

See the Werkzeug documentation for further information on ``LocalProxy``:

    http://werkzeug.pocoo.org/docs/0.14/local/#werkzeug.local.LocalProxy
"""

from addict import Dict
import flask
from werkzeug.local import LocalProxy

from fence.auth import current_token
from fence.models import User


def _get_current_username():
    """
    Get the username for the current user from one of these places (listed in
    descending priority):
    - ``current_token``, the token in request headers
    - the ``MOCK_AUTH`` token
    - the session token

    Return:
        Optional[str]: the username, or None if no username could be found
    """
    username = flask.session.get('username')
    if current_token:
        username = current_token['context']['user']['name']
    else:
        mock_auth_token = flask.current_app.config.get('MOCK_AUTH')
        if mock_auth_token:
            username = mock_auth_token['context']['user']['name']
    return username


def _get_user(username):
    """
    Look up the user with the given username, and return a dictionary
    containing all the information for the user.

    Args:
        username (Optional[str]): the username to lookup

    Return:
        Optional[addict.Dict]:
            attribute dictionary of everything on the ``User`` model
    """
    if not username:
        return None
    with flask.current_app.db.session as session:
        user = session.query(User).filter_by(username=username).first()
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
        flask.g._current_user = _get_user(_get_current_username())
    return flask.g._current_user


current_user = LocalProxy(_get_and_set_current_user)
