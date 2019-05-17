import flask
from flask_restful import Resource

from fence.auth import login_user
from fence.errors import Unauthorized
from fence.jwt.validate import validate_jwt
from fence.models import IdentityProvider


class FenceRedirect(Resource):
    """
    For ``/login/fence`` endpoint.

    Redirect to the authorization URL for the IDP fence app.

    The provider fence should redirect back to ``/login/fence/login`` (see the
    second resource below) so that this client fence can finish the login.
    Also, if this client fence instance should redirect back to a URL from the
    original OAuth client, record that for the next step.
    """

    def get(self):
        """Handle ``GET /login/fence``."""
        oauth2_redirect_uri = flask.current_app.fence_client.client_kwargs.get(
            "redirect_uri"
        )
        redirect_url = flask.request.args.get("redirect")
        if redirect_url:
            flask.session["redirect"] = redirect_url
        authorization_url, state = flask.current_app.fence_client.generate_authorize_redirect(
            oauth2_redirect_uri
        )
        flask.session["state"] = state
        return flask.redirect(authorization_url)


class FenceLogin(Resource):
    """
    For ``/login/fence/login`` endpoint.

    The IDP fence app should redirect back to here with an authorization grant.
    """

    def get(self):
        """Handle ``GET /login/fence/login``."""
        # Check that the state passed back from IDP fence is the same as the
        # one stored previously.
        mismatched_state = (
            "state" not in flask.request.args
            or "state" not in flask.session
            or flask.request.args["state"] != flask.session.pop("state", "")
        )
        if mismatched_state:
            raise Unauthorized(
                "Login flow was interrupted (state mismatch). Please go back to the"
                " login page for the original application to continue."
            )
        # Get the token response and log in the user.
        redirect_uri = flask.current_app.fence_client._get_session().redirect_uri
        tokens = flask.current_app.fence_client.fetch_access_token(
            redirect_uri, **flask.request.args.to_dict()
        )
        id_token_claims = validate_jwt(
            tokens["id_token"], aud={"openid"}, purpose="id", attempt_refresh=True
        )
        username = id_token_claims["context"]["user"]["name"]
        login_user(flask.request, username, IdentityProvider.fence)

        if "redirect" in flask.session:
            return flask.redirect(flask.session.get("redirect"))
        return flask.jsonify({"username": username})
