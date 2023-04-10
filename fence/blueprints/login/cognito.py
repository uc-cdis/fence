import flask

from fence.blueprints.login.base import (
    DefaultOAuth2Login,
    DefaultOAuth2Callback,
    _login,
    prepare_login_log,
)
from fence.models import IdentityProvider


class CognitoLogin(DefaultOAuth2Login):
    def __init__(self):
        super(CognitoLogin, self).__init__(
            idp_name=IdentityProvider.cognito, client=flask.current_app.cognito_client
        )


class CognitoCallback(DefaultOAuth2Callback):
    def __init__(self):
        super(CognitoCallback, self).__init__(
            idp_name=IdentityProvider.cognito, client=flask.current_app.cognito_client
        )
