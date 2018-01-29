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

from fence.jwt import token, errors
from fence.models import Client
from fence.oidc.server import server
from fence.user import get_current_user


blueprint = flask.Blueprint('oauth2', __name__)


@blueprint.route('/authorize', methods=['GET', 'POST'])
def authorize(*args, **kwargs):
    user = get_current_user()

    if flask.request.method == 'GET':
        grant = server.validate_authorization_request()

        client_id = grant.params.get('client_id')
        with flask.current_app.db.session as session:
            client = (
                session
                .query(Client)
                .filter_by(client_id=client_id)
                .first()
            )
            scope = flask.request.args.get('scope')
        return flask.render_template(
            'oauthorize.html', grant=grant, user=user, client=client,
            scope=scope
        )

    if flask.request.form.get('confirm'):
        return server.create_authorization_response(user)
    else:
        return server.create_authorization_response(None)


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
