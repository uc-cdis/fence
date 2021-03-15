from authlib.common.urls import add_params_to_uri
import flask

from fence.auth import login_user
from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback
from fence.blueprints.login.redirect import validate_redirect
from fence.config import config
from fence.errors import Unauthorized
from fence.jwt.validate import validate_jwt
from fence.models import IdentityProvider


class FenceLogin(DefaultOAuth2Login):
    """
    For ``/login/fence`` endpoint.

    Redirect to the authorization URL for the IDP fence app.

    The provider fence should redirect back to ``/login/fence/login`` (see the
    second resource below) so that this client fence can finish the login.
    Also, if this client fence instance should redirect back to a URL from the
    original OAuth client, record that for the next step.
    """

    def __init__(self):
        super(FenceLogin, self).__init__(
            idp_name=IdentityProvider.fence, client=flask.current_app.fence_client
        )

    def get(self):
        """Handle ``GET /login/fence``."""
        oauth2_redirect_uri = flask.current_app.fence_client.client_kwargs.get(
            "redirect_uri"
        )
        redirect_url = flask.request.args.get("redirect")
        if redirect_url:
            validate_redirect(redirect_url)
            flask.session["redirect"] = redirect_url
        (
            authorization_url,
            state,
        ) = flask.current_app.fence_client.generate_authorize_redirect(
            oauth2_redirect_uri, prompt="login"
        )

        # add idp parameter to the authorization URL
        if "idp" in flask.request.args:
            idp = flask.request.args["idp"]
            flask.session["fence_idp"] = idp
            params = {"idp": idp}
            # if requesting to login through Shibboleth, also add shib_idp
            # parameter to the authorization URL
            if idp == "shibboleth" and "shib_idp" in flask.request.args:
                shib_idp = flask.request.args["shib_idp"]
                params["shib_idp"] = shib_idp
                flask.session["shib_idp"] = shib_idp
            authorization_url = add_params_to_uri(authorization_url, params)

        flask.session["state"] = state
        return flask.redirect(authorization_url)


class FenceCallback(DefaultOAuth2Callback):
    """
    For ``/login/fence/login`` endpoint.

    The IDP fence app should redirect back to here with an authorization grant.
    """

    def __init__(self):
        super(FenceCallback, self).__init__(
            idp_name=IdentityProvider.fence, client=flask.current_app.fence_client
        )

    def get(self):
        """Handle ``GET /login/fence/login``."""
        # Check that the state passed back from IDP fence is the same as the
        # one stored previously.
        mismatched_state = (
            "state" not in flask.request.args
            or "state" not in flask.session
            or flask.request.args["state"] != flask.session.pop("state", "")
        )
        if mismatched_state and not config.get("MOCK_AUTH"):
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
        login_user(
            username,
            IdentityProvider.fence,
            fence_idp=flask.session.get("fence_idp"),
            shib_idp=flask.session.get("shib_idp"),
        )
        self.post_login()

        if "redirect" in flask.session:
            return flask.redirect(flask.session.get("redirect"))
        return flask.jsonify({"username": username})
