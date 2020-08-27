import flask

from fence.models import IdentityProvider
from fence.resources.openid.okta_oauth2 import OKTA_IDP_NAME
from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback


class OktaLogin(DefaultOAuth2Login):
    def __init__(self):
        super(OktaLogin, self).__init__(
            idp_name=OKTA_IDP_NAME,
            client=flask.current_app.okta_client,
        )


class OktaCallback(DefaultOAuth2Callback):
    def __init__(self):
        super(OktaCallback, self).__init__(
            idp_name=OKTA_IDP_NAME,
            client=flask.current_app.okta_client,
        )
