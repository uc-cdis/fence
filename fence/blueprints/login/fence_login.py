from authutils.token.validate import validate_jwt
import flask
from flask_restful import Resource

from fence.auth import login_user, validate_local_redirect
from fence.errors import Unauthorized
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
        oauth2_redirect_uri = (
            flask.current_app.fence_client.session.redirect_uri
        )

        # The access token is provided in a session cookie and there should
        # be no reason to redirect to a domain that can't access it.
        # Make sure the URLs look legit before we think about redirecting.
        on_error_url = flask.request.args.get('on_error')
        redirect_url = flask.request.args.get('redirect')
        if redirect_url:
            flask.session['redirect'] = validate_local_redirect(redirect_url)
        if on_error_url:
            flask.session['on_error'] = validate_local_redirect(on_error_url)

        authorization_url, state = (
            flask.current_app
            .fence_client
            .generate_authorize_redirect(oauth2_redirect_uri)
        )
        flask.session['state'] = state
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
            'state' not in flask.request.args
            or 'state' not in flask.session
            or flask.request.args['state'] != flask.session.pop('state', '')
        )
        if mismatched_state:
            raise Unauthorized('authorization request failed; state mismatch')
        # Get the token response and log in the user.
        redirect_uri = flask.current_app.fence_client.session.redirect_uri
        tokens = flask.current_app.fence_client.fetch_access_token(
            redirect_uri, **flask.request.args.to_dict()
        )
        id_token_claims = validate_jwt(
            tokens['id_token'], aud={'openid'}, purpose='id',
            attempt_refresh=True
        )
        username = id_token_claims['context']['user']['name']
        flask.session['username'] = username
        flask.session['provider'] = IdentityProvider.fence
        login_user(flask.request, username, IdentityProvider.fence)

        if 'redirect' in flask.session:
            return flask.redirect(flask.session.get('redirect'))
        return flask.jsonify({'username': username})
