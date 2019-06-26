import flask
from flask_restful import Resource

from fence.auth import login_user
from fence.blueprints.login.redirect import validate_redirect
from fence.errors import InternalError, Unauthorized
from fence.models import IdentityProvider
from fence.config import config


class ShibbolethLogin(Resource):
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
        if not entityID:
            # default to SSO_URL from the config which should be NIH login
            actual_redirect = config["BASE_URL"] + "/login/shib/login"
            return flask.redirect(config["SSO_URL"] + actual_redirect)
        return flask.redirect(
            config["BASE_URL"] + "/Shibboleth.sso/Login?entityID={}".format(entityID)
        )


class ShibbolethCallback(Resource):
    def get(self):
        """
        Complete the shibboleth login.
        """
        if "SHIBBOLETH_HEADER" not in config:
            raise InternalError("Missing shibboleth header configuration")
        eppn = flask.request.headers.get(config["SHIBBOLETH_HEADER"])
        username = eppn.split("!")[-1] if eppn else None
        if not username:
            raise Unauthorized("Please login")
        idp = IdentityProvider.itrust
        if flask.session.get("entityID"):
            idp = flask.session.get("entityID")
        login_user(flask.request, username, idp)
        if flask.session.get("redirect"):
            return flask.redirect(flask.session.get("redirect"))
        return "logged in"
