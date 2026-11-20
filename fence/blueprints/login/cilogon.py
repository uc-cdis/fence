import flask

from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback
from fence.config import config

CILOGON_IDP_NAME = "cilogon"


class CilogonLogin(DefaultOAuth2Login):
    def __init__(self):
        super(CilogonLogin, self).__init__(
            idp_name=CILOGON_IDP_NAME, client=flask.current_app.cilogon_client
        )


class CilogonCallback(DefaultOAuth2Callback):
    def __init__(self):
        # use the configured `user_id_field` if there is one, otherwise default to "sub"
        username_field = (
            config["OPENID_CONNECT"].get(CILOGON_IDP_NAME, {}).get("user_id_field")
            or "sub"
        )
        super(CilogonCallback, self).__init__(
            idp_name=CILOGON_IDP_NAME,
            client=flask.current_app.cilogon_client,
            username_field=username_field,
        )
