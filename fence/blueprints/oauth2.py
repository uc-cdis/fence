# pylint: disable=protected-access,unused-argument
"""
Define the ``OAuth2Provider`` used by fence and set its related handler
functions for storing and loading ``Grant`` models and loading ``Client``
models.

In the implementation here with JWT, a grant is a thin wrapper around the
client from which an authorization request was issued, and the code being used
for a specific request; additionally, the grant is able to throw itself away
when the procedure is completed or after a short timeout.

The token setter and getter functions for the OAuth provider do pretty much
nothing, since the JWTs contain all the necessary information and are
stateless.
"""

import flask

from authlib.common.urls import add_params_to_uri
from authlib.specs.rfc6749.errors import AccessDeniedError
from authlib.specs.rfc6749.errors import InvalidRequestError

from fence.errors import Unauthorized
from fence.models import Client
from fence.oidc.server import server
from fence.user import get_current_user
from fence.auth import handle_login

blueprint = flask.Blueprint('oauth2', __name__)


@blueprint.route('/authorize', methods=['GET', 'POST'])
def authorize(*args, **kwargs):
    try:
        user = get_current_user()
    except Unauthorized:
        user = None

    if user:
        grant = server.validate_authorization_request()

        if grant.params.get('confirm') is not None:
            response = _handle_consent_confirmation(
                user, grant.params.get('confirm'))
        else:
            # no confirm param, so no confirmation has occured yet
            response = _authorize(user, grant.params)

    else:
        response = server.create_authorization_response(None)

    return response


def _handle_consent_confirmation(user, is_confirmed):
    if is_confirmed == 'yes':
        # user has already given consent, continue flow
        response = server.create_authorization_response(user)
    else:
        # user did not give consent
        response = server.create_authorization_response(None)
    return response


def _authorize(user, grant):
    grant = server.validate_authorization_request()
    prompts = grant.params.get('prompt')
    client_id = grant.params.get('client_id')

    with flask.current_app.db.session as session:
        client = (
            session
                .query(Client)
                .filter_by(client_id=client_id)
                .first()
        )
        scope = flask.request.args.get('scope')

    response = _get_auth_response_for_prompts(prompts, grant, user, client, scope)

    return response


def _get_auth_response_for_prompts(prompts, grant, user, client, scope):
    show_consent_screen = True

    if prompts:
        prompts = prompts.split(' ')
        if 'none' in prompts:
            # don't auth or consent, error if user not logged in
            show_consent_screen = False

            # if none is here, there shouldn't be others
            if len(prompts) != 1:
                error = InvalidRequestError(
                    state=grant.params.get('state'), uri=grant.params.get('uri'))
                return _get_authorize_error_response(
                    error, grant.params.get('redirect_uri'))

            try:
                get_current_user()
                response = server.create_authorization_response(user)
            except Unauthorized:
                error = AccessDeniedError(
                    state=grant.params.get('state'), uri=grant.params.get('uri'))
                return _get_authorize_error_response(
                    error, grant.params.get('redirect_uri'))

        if 'login' in prompts:
            show_consent_screen = True
            try:
                # re-AuthN user
                handle_login(scope)  # TODO not sure if this really counts as re-AuthN...
            except Unauthorized:
                error = AccessDeniedError(
                    state=grant.params.get('state'), uri=grant.params.get('uri'))
                return _get_authorize_error_response(
                    error, grant.params.get('redirect_uri'))

        if 'consent' in prompts:
            # show consent screen (which is default behavior so pass)
            pass

        if 'select_account' in prompts:
            # allow user to select one of their accounts, we
            # don't support this at the moment
            pass

    if show_consent_screen:
        response = flask.render_template(
            'oauthorize.html', grant=grant, user=user, client=client,
            scope=scope
        )

    return response


def _get_authorize_error_response(error, redirect_uri):
    params = error.get_body()
    uri = add_params_to_uri(redirect_uri, params)
    headers = [('Location', uri)]
    response = flask.Response('', status=302, headers=headers)
    return response


@blueprint.route('/token', methods=['POST'])
def get_access_token(*args, **kwargs):
    """
    Handle exchanging code for and refreshing the access token.

    The operation here is handled entirely by the ``oauth.token_handler``
    decorator, so this function only needs to pass.

    See the OpenAPI documentation for detailed specification, and the OAuth2
    tests for examples of some operation and correct behavior.
    """
    return server.create_token_response()


@blueprint.route('/revoke', methods=['POST'])
def revoke_token():
    """
    Revoke a refresh token.

    If the operation is successful, return an empty response with a 204 status
    code. Otherwise, return error message in JSON with a 400 code.

    Return:
        Tuple[str, int]: JSON response and status code
    """
    return server.create_revocation_response()


@blueprint.route('/errors', methods=['GET'])
def display_error():
    """
    Define the errors endpoint for the OAuth provider.
    """
    return flask.jsonify(flask.request.args)
