import flask

from fence.models import IdentityProvider
from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback


class MicrosoftLogin(DefaultOAuth2Login):
    def __init__(self):
        super(MicrosoftLogin, self).__init__(
            idp_name=IdentityProvider.microsoft,
            client=flask.current_app.microsoft_client,
        )


class MicrosoftCallback(DefaultOAuth2Callback):
    def __init__(self):
        super(MicrosoftCallback, self).__init__(
            idp_name=IdentityProvider.microsoft,
            client=flask.current_app.microsoft_client,
        )
