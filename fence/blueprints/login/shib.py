from cdislogging import get_logger
import flask
from flask_restful import Resource

from fence.auth import login_user
from fence.errors import InternalError, Unauthorized
from fence.models import IdentityProvider
from fence.config import config


logger = get_logger(__name__)


class ShibbolethLoginStart(Resource):
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
        if redirect_url:
            flask.session["redirect"] = redirect_url

        # figure out which IDP to target with shibboleth
        # check out shibboleth docs here for more info:
        # https://wiki.shibboleth.net/confluence/display/SP3/SSO
        entityID = flask.request.args.get("shib_idp")
        flask.session["entityID"] = entityID
        actual_redirect = config["BASE_URL"] + "/login/shib/login"
        if not entityID or entityID == "urn:mace:incommon:nih.gov":
            # default to SSO_URL from the config which should be NIH login
            return flask.redirect(config["SSO_URL"] + actual_redirect)
        return flask.redirect(
            config["BASE_URL"]
            + "/Shibboleth.sso/Login?entityID={}&target={}".format(
                entityID, actual_redirect
            )
        )


class ShibbolethLoginFinish(Resource):
    def get(self):
        """
        Complete the shibboleth login.
        """
        if "SHIBBOLETH_HEADER" not in config:
            raise InternalError("Missing shibboleth header configuration")
        username = flask.request.headers.get("eppn")
        if not username or (not entityID or entityID == "urn:mace:incommon:nih.gov"):
            persistent_id = flask.request.headers.get(config["SHIBBOLETH_HEADER"])
            username = persistent_id.split("!")[-1] if persistent_id else None
            if not username:
                raise Unauthorized("Please login")
        idp = IdentityProvider.itrust
        if flask.session.get("entityID"):
            idp = flask.session.get("entityID")
        login_user(flask.request, username, idp)
        if flask.session.get("redirect"):
            return flask.redirect(flask.session.get("redirect"))
        return "logged in"
