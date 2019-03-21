import flask

from fence.models import IdentityProvider
from fence.blueprints.login._default import DefaultLogin, DefaultCallback


class MicrosoftLogin(DefaultLogin):
    def __init__(self):
        super(MicrosoftLogin, self).__init__(
            idp_name=IdentityProvider.microsoft,
            client=flask.current_app.microsoft_client,
        )


class MicrosoftCallback(DefaultCallback):
    def __init__(self):
        super(MicrosoftCallback, self).__init__(
            idp_name=IdentityProvider.microsoft,
            client=flask.current_app.microsoft_client,
        )
