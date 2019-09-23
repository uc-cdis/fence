from datetime import datetime, timezone, timedelta

import flask
from flask_sqlalchemy_session import current_session

from fence.config import config
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
            idp_name=IdentityProvider.synapse, client=flask.current_app.synapse_client
        )

    def post_login(self, user, token_result):
        user.id_from_idp = token_result["sub"]
        user.display_name = "{given_name} {family_name}".format(**token_result)
        if user.additional_info is None:
            user.additional_info = {}
        user.additional_info.update(token_result)
        current_session.add(user)
        current_session.commit()

        with flask.current_app.arborist.context(authz_provider="synapse"):
            if config["DREAM_CHALLENGE_TEAM"] in token_result.get("team", []):
                flask.current_app.arborist.add_user_to_group(
                    user.username,
                    config["DREAM_CHALLENGE_GROUP"],
                    datetime.now(timezone.utc)
                    + timedelta(seconds=config["SYNAPSE_AUTHZ_TTL"]),
                )
            else:
                flask.current_app.arborist.remove_user_from_group(
                    user.username, config["DREAM_CHALLENGE_GROUP"]
                )
