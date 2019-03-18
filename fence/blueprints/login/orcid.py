import flask
from flask_restful import Resource

from fence.auth import login_user
from fence.errors import UserError
from fence.models import IdentityProvider
from fence.config import config


class ORCIDRedirect(Resource):
    def get(self):
        flask.redirect_url = flask.request.args.get("redirect")
        if flask.redirect_url:
            flask.session["redirect"] = flask.redirect_url

        if config.get("MOCK_ORCID_AUTH", False):
            orcid = flask.request.cookies.get(
                config.get("DEV_LOGIN_COOKIE_NAME"), "0000-0002-2601-8132"
            )
            return _login(orcid)

        return flask.redirect(flask.current_app.orcid_client.get_auth_url())


class ORCIDLogin(Resource):
    def get(self):
        code = flask.request.args.get("code")
        result = flask.current_app.orcid_client.get_user_id(code)
        if result:
            return _login(result)
        raise UserError(result)


def _login(orcid):
    """
    Login user with given email from ORCID, then redirect if session has a saved
    redirect.
    """
    login_user(flask.request, orcid, IdentityProvider.orcid)
    if flask.session.get("redirect"):
        return flask.redirect(flask.session.get("redirect"))
    return flask.jsonify({"username": orcid})
