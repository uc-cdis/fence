import flask
from flask_sqlalchemy_session import current_session

from fence.errors import Unauthorized
from fence.models import User


def get_current_user():
    username = flask.session.get('username')
    if not username:
        eppn = flask.request.headers.get(
            flask.current_app.config['SHIBBOLETH_HEADER']
        )
        if flask.current_app.config.get('MOCK_AUTH') is True:
            eppn = 'test'
        if eppn:
            username = eppn.split('!')[-1]
        else:
            raise Unauthorized("User not logged in")
    return (
        current_session.query(User)
        .filter(User.username == username)
        .first()
    )
