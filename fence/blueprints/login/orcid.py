import flask

from fence.models import IdentityProvider

from fence.blueprints.login._default import DefaultLogin, DefaultCallback


class ORCIDLogin(DefaultLogin):
    def __init__(self):
        super(ORCIDLogin, self).__init__(
            idp_name=IdentityProvider.microsoft,
            client=flask.current_app.orcid_client,
            mock_username="0000-0002-2601-8132",
        )


class ORCIDCallback(DefaultCallback):
    def __init__(self):
        super(ORCIDCallback, self).__init__(
            idp_name=IdentityProvider.microsoft, client=flask.current_app.orcid_client
        )
