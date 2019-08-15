import flask
from flask_sqlalchemy_session import current_session

from fence.models import IdentityProvider

from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback


class SynapseLogin(DefaultOAuth2Login):
    def __init__(self):
        super(SynapseLogin, self).__init__(
            idp_name=IdentityProvider.synapse, client=flask.current_app.synapse_client
        )


class SynapseCallback(DefaultOAuth2Callback):
    def __init__(self):
        super(SynapseCallback, self).__init__(
            idp_name=IdentityProvider.synapse,
            client=flask.current_app.synapse_client,
        )

    def post_login(self, user, token_result):
        user.id_from_idp = token_result["sub"]
        user.display_name = "{given_name} {family_name}".format(**token_result)
        current_session.add(user)
        current_session.commit()

        # TODO
        # company
        # team
        # exp
