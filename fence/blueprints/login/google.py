import flask
from flask_restful import Resource

from fence.auth import login_user
from fence.errors import UserError
from fence.models import IdentityProvider


class GoogleRedirect(Resource):
    def get(self):
        flask.redirect_url = flask.request.args.get("redirect")
        if flask.redirect_url:
            flask.session["redirect"] = flask.redirect_url
        return flask.redirect(flask.current_app.google_client.get_auth_url())


class GoogleLogin(Resource):
    def get(self):
        # Check if this is a request to link account vs. actually log in
        if flask.session.get("google_link"):
            return flask.redirect(
                flask.current_app.config.get("BASE_URL", "")
                + "/link/google/callback?code={}".format(flask.request.args.get("code"))
            )
        else:
            code = flask.request.args.get("code")
            result = flask.current_app.google_client.get_user_id(code)
            email = result.get("email")
            if email:
                login_user(flask.request, email, IdentityProvider.google)
                if flask.session.get("redirect"):
                    return flask.redirect(flask.session.get("redirect"))
                return flask.jsonify({"username": email})
            raise UserError(result)
