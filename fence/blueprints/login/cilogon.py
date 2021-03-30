import flask

from fence.resources.openid.cilogon_oauth2 import CILOGON_IDP_NAME
from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback


class CilogonLogin(DefaultOAuth2Login):
    def __init__(self):
        super(CilogonLogin, self).__init__(
            idp_name=CILOGON_IDP_NAME, client=flask.current_app.cilogon_client
        )


class CilogonCallback(DefaultOAuth2Callback):
    def __init__(self):
        super(CilogonCallback, self).__init__(
            idp_name=CILOGON_IDP_NAME,
            client=flask.current_app.cilogon_client,
            username_field="sub",
        )
