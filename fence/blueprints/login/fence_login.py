from cdislogging import get_logger
import flask
from flask_restful import Resource
import requests

from fence.auth import login_user
from fence.blueprints.login.redirect import validate_redirect
from fence.config import config
from fence.errors import Unauthorized, NotFound
from fence.jwt.validate import validate_jwt
from fence.models import IdentityProvider


logger = get_logger(__name__)


class FenceLogin(Resource):
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
            validate_redirect(redirect_url)
            flask.session["redirect"] = redirect_url
        authorization_url, state = flask.current_app.fence_client.generate_authorize_redirect(
            oauth2_redirect_uri, prompt="login"
        )
        flask.session["state"] = state
        return flask.redirect(authorization_url)


class FenceCallback(Resource):
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


class FenceDownstreamIDPs(Resource):
    """
    For ``/login/downstream-idps`` endpoint.

    Should only be enabled if the fence IDP is using shibboleth.
    """

    def get(self):
        """Handle ``GET /login/downstream-idps``."""
        try:
            content = get_disco_feed()
        except EnvironmentError:
            return flask.Response(
                response=flask.jsonify(
                    {"error": "couldn't reach endpoint on shibboleth provider"}
                ),
                status=500,
            )
        if not content:
            raise NotFound("this endpoint is unavailable")
        return flask.jsonify(content)

def get_disco_feed():
    """
    For fence instances which point to a fence instance deployed with shibboleth IDP(s),
    we want to list the available downstream IDPs that could be used for shibboleth
    login. The `entityID` from the DiscoFeed can be provided to the /login/shib
    endpoint, e.g. (without urlencoding):

        /login/shib?shib_idp=urn:mace:incommon:uchicago.edu

    where `urn:mace:incommon:uchicago.edu` is the `entityID` according to shibboleth.

    Return:
        Optional[dict]:
            json response from the /Shibboleth.sso/DiscoFeed endpoint on the IDP fence;
            or None if there is no fence IDP or if it returns 404 for DiscoFeed

    Raises:
        EnvironmentError: if the response is bad
    """
    # must be configured for fence IDP
    fence_idp_url = config["OPENID_CONNECT"].get("fence", {}).get("api_base_url")
    if not fence_idp_url:
        return None
    disco_feed_url = fence_idp_url.rstrip("/") + "/Shibboleth.sso/DiscoFeed"
    try:
        response = requests.get(disco_feed_url, timeout=3)
    except requests.RequestException:
        raise EnvironmentError("couldn't reach fence IDP")
    if response.status_code != 200:
        # if it's 404 that's fine---just no shibboleth. otherwise there could be an
        # actual problem
        if response.status_code != 404:
            logger.error(
                "got weird response ({}) from the IDP fence shibboleth disco feed ({})"
                .format(response.status_code, disco_feed_url)
            )
            raise EnvironmentError("unexpected response from fence IDP")
        return None
    try:
        return response.json()
    except ValueError:
        logger.error(
            "didn't get JSON in response from IDP fence shibboleth disco feed ({})"
            .format(disco_feed_url)
        )
        return None
