import flask
from flask_restful import Resource

from fence.auth import login_user
from fence.errors import InternalError, Unauthorized
from fence.models import IdentityProvider
from fence.config import config


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
        actual_redirect = config["BASE_URL"] + "/login/shib/login"
        return flask.redirect(config["SSO_URL"] + actual_redirect)


class ShibbolethLoginFinish(Resource):
    def get(self):
        """
        Complete the shibboleth login.
        """

        if "SHIBBOLETH_HEADER" in config:
            eppn = flask.request.headers.get(config["SHIBBOLETH_HEADER"])

        else:
            raise InternalError("Missing shibboleth header configuration")
        username = eppn.split("!")[-1] if eppn else None
        if username:
            login_user(flask.request, username, IdentityProvider.itrust)
            if flask.session.get("redirect"):
                return flask.redirect(flask.session.get("redirect"))
            return "logged in"
        else:
            raise Unauthorized("Please login")
