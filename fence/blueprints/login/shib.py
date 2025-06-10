from cdislogging import get_logger
import flask

from fence.auth import login_user
from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback
from fence.blueprints.login.redirect import validate_redirect
from fence.errors import InternalError, Unauthorized
from fence.models import IdentityProvider
from fence.config import config

logger = get_logger(__name__)


class ShibbolethLogin(DefaultOAuth2Login):
    def __init__(self):
        super(ShibbolethLogin, self).__init__(
            idp_name=IdentityProvider.itrust, client=None
        )

    def get(self):
        """
        The login flow is:
        user
        -> {fence}/login/shib?redirect={portal}
        -> user login at {nih_shibboleth_idp}
        -> nih idp POST to fence shibboleth and establish a shibboleth sp
           session
        -> redirect to {fence}/login/shib/login that sets up fence session
        -> redirect to portal
        """
        redirect_url = flask.request.args.get("redirect")
        validate_redirect(redirect_url)
        if redirect_url:
            flask.session["redirect"] = redirect_url

        # figure out which IDP to target with shibboleth
        # check out shibboleth docs here for more info:
        # https://wiki.shibboleth.net/confluence/display/SP3/SSO
        entityID = flask.request.args.get("shib_idp")
        flask.session["entityID"] = entityID
        # TODO: use OPENID_CONNECT.shibboleth.redirect_url instead of hardcoded
        actual_redirect = config["BASE_URL"] + "/login/shib/login"
        if (
            not entityID
            or entityID == "urn:mace:incommon:nih.gov"
            or entityID == "https://auth.nih.gov/IDP"
        ):
            # default to SSO_URL from the config which should be NIH login
            return flask.redirect(config["SSO_URL"] + actual_redirect)
        return flask.redirect(
            config["BASE_URL"]
            + "/Shibboleth.sso/Login?entityID={}&target={}".format(
                entityID, actual_redirect
            )
        )


class ShibbolethCallback(DefaultOAuth2Callback):
    def __init__(self):
        super(ShibbolethCallback, self).__init__(
            idp_name=IdentityProvider.itrust, client=None
        )

    def get(self):
        """
        Complete the shibboleth login.
        """
        shib_header = config.get("SHIBBOLETH_HEADER")
        if not shib_header:
            raise InternalError("Missing shibboleth header configuration")

        # eppn stands for eduPersonPrincipalName
        username = flask.request.headers.get("eppn")
        entityID = flask.session.get("entityID")

        # if eppn not available or logging in through NIH
        if (
            not username
            or not entityID
            or entityID == "urn:mace:incommon:nih.gov"
            or entityID == "https://auth.nih.gov/IDP"
        ):
            persistent_id = flask.request.headers.get(shib_header)
            username = persistent_id.split("!")[-1] if persistent_id else None
            if not username:
                # some inCommon providers are not returning eppn
                # or persistent_id. See PXP-4309
                # print("shib_header", shib_header)
                # print("flask.request.headers", flask.request.headers)
                raise Unauthorized("Unable to retrieve username")

        idp = IdentityProvider.itrust
        if entityID:
            idp = entityID
        login_user(username, idp)
        self.post_login()

        if flask.session.get("redirect"):
            return flask.redirect(flask.session.get("redirect"))

        return "logged in"
