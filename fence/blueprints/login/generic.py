import flask

from fence.models import IdentityProvider
from fence.resources.openid.generic_oauth2 import GENERIC_IDP_NAME
from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback


class GenericLogin(DefaultOAuth2Login):
    def __init__(self):
        super(GenericLogin, self).__init__(
            idp_name=GENERIC_IDP_NAME,
            client=flask.current_app.generic_client,
        )


class GenericCallback(DefaultOAuth2Callback):
    def __init__(self):
        super(GenericCallback, self).__init__(
            idp_name=GENERIC_IDP_NAME,
            client=flask.current_app.generic_client,
        )
