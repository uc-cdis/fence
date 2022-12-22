import flask
from cdislogging import get_logger
from flask_sqlalchemy_session import current_session

import fence.resources.cognito.groups
from fence.blueprints.login.base import DefaultOAuth2Callback, DefaultOAuth2Login
from fence.config import config
from fence.models import IdentityProvider

logger = get_logger(__name__)


class CognitoLogin(DefaultOAuth2Login):
    def __init__(self):
        super(CognitoLogin, self).__init__(
            idp_name=IdentityProvider.cognito, client=flask.current_app.cognito_client
        )


class CognitoCallback(DefaultOAuth2Callback):
    def __init__(self):
        super(CognitoCallback, self).__init__(
            idp_name=IdentityProvider.cognito, client=flask.current_app.cognito_client
        )

    def post_login(self, user=None, token_result=None, id_from_idp=None):
        userinfo = flask.g.userinfo

        email = userinfo.get("email")

        assign_groups_as_policies = config["cognito"]["assign_groups_as_policies"]
        assign_groups_claim_name = config["cognito"]["assign_groups_claim_name"]

        if assign_groups_as_policies:
            try:
                groups = flask.current_app.cognito_client.get_group_claims(
                    userinfo, assign_groups_claim_name
                )
            except Exception as e:
                err_msg = "Could not retrieve groups"
                logger.error("{}: {}".format(e, err_msg))
                raise

            fence.resources.cognito.groups.sync_gen3_users_authz_from_adfs_groups(
                email,
                groups,
                db_session=current_session,
            )

        super(CognitoCallback, self).post_login(id_from_idp=id_from_idp)
