import flask

from fence.models import IdentityProvider

from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback


class ORCIDLogin(DefaultOAuth2Login):
    def __init__(self):
        super(ORCIDLogin, self).__init__(
            idp_name=IdentityProvider.orcid,
            client=flask.current_app.orcid_client,
            mock_username="0000-0002-2601-8132",
        )


class ORCIDCallback(DefaultOAuth2Callback):
    def __init__(self):
        super(ORCIDCallback, self).__init__(
            idp_name=IdentityProvider.orcid,
            client=flask.current_app.orcid_client,
            username_field="orcid",
        )
