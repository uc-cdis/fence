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
from authlib.specs.rfc6749.errors import (
    AccessDeniedError,
    InvalidRequestError,
    OAuth2Error,
)

from fence.errors import Unauthorized
from fence.jwt.token import SCOPE_DESCRIPTION
from fence.models import Client
from fence.oidc.server import server
from fence.utils import clear_cookies
from fence.user import get_current_user


blueprint = flask.Blueprint("oauth2", __name__)


@blueprint.route("/authorize", methods=["GET", "POST"])
def authorize(*args, **kwargs):
    """
    OIDC Authorization Endpoint

    From the OIDC Specification:

    3.1.1.  Authorization Code Flow Steps
    The Authorization Code Flow goes through the following steps.

    - Client prepares an Authentication Request containing the desired request
      parameters.
    - Client sends the request to the Authorization Server.
    - Authorization Server Authenticates the End-User.
    - Authorization Server obtains End-User Consent/Authorization.
    - Authorization Server sends the End-User back to the Client with an
      Authorization Code.
    - Client requests a response using the Authorization Code at the Token
      Endpoint.
    - Client receives a response that contains an ID Token and Access Token in
      the response body.
    - Client validates the ID token and retrieves the End-User's Subject
      Identifier.

    Args:
        *args: additional arguments
        **kwargs: additional keyword arguments
    """
    need_authentication = False
    try:
        user = get_current_user()
    except Unauthorized:
        need_authentication = True

    if need_authentication or not user:
        redirect_url = (
            flask.current_app.config.get("BASE_URL") + flask.request.full_path
        )
        params = {"redirect": redirect_url}
        login_url = add_params_to_uri(
            flask.current_app.config.get("DEFAULT_LOGIN_URL"), params
        )
        return flask.redirect(login_url)

    try:
        grant = server.validate_authorization_request()
    except OAuth2Error as e:
        raise Unauthorized("{} failed to authorize".format(str(e)))

    client_id = grant.params.get("client_id")

    with flask.current_app.db.session as session:
        client = session.query(Client).filter_by(client_id=client_id).first()

    confirm = grant.params.get("confirm")
    if client.auto_approve:
        confirm = "yes"
    if confirm is not None:
        response = _handle_consent_confirmation(user, confirm)
        # if it's a 302 for POST confirm, return 200 instead and include
        # redirect url in body because browser ajax POST doesn't follow
        # cross origin redirect
        if flask.request.method == "POST" and response.status_code == 302:
            return flask.jsonify({"redirect": response.headers["Location"]})
    else:
        # no confirm param, so no confirmation has occured yet
        response = _authorize(user, grant, client)

    return response


def _handle_consent_confirmation(user, is_confirmed):
    """
    Return server response given user consent.

    Args:
        user (fence.models.User): authN'd user
        is_confirmed (str): confirmation param
    """
    if is_confirmed == "yes":
        # user has already given consent, continue flow
        response = server.create_authorization_response(user)
    else:
        # user did not give consent
        response = server.create_authorization_response(None)
    return response


def _authorize(user, grant, client):
    """
    Return server response when user has not yet provided consent.

    Args:
        user (fence.models.User): authN'd user
        grant (fence.oidc.grants.AuthorizationCodeGrant): request grant
        client (fence.models.Client): request client
    """
    prompts = grant.params.get("prompt")

    scope = flask.request.args.get("scope")

    response = _get_auth_response_for_prompts(prompts, grant, user, client, scope)

    return response


def _get_auth_response_for_prompts(prompts, grant, user, client, scope):
    """
    Get response based on prompt parameter. TODO: not completely conforming yet

    FIXME: To conform to spec, some of the prompt params should be handled
    before AuthN or if it fails (so adequate and useful errors are provided).

    Right now the behavior is that the endpoint will just continue to
    redirect the user to log in without checking these params....

    Args:
        prompts (TYPE): Description
        grant (TYPE): Description
        user (TYPE): Description
        client (TYPE): Description
        scope (TYPE): Description

    Returns:
        TYPE: Description
    """
    show_consent_screen = True

    if prompts:
        prompts = prompts.split(" ")
        if "none" in prompts:
            # don't auth or consent, error if user not logged in
            show_consent_screen = False

            # if none is here, there shouldn't be others
            if len(prompts) != 1:
                error = InvalidRequestError(
                    state=grant.params.get("state"), uri=grant.params.get("uri")
                )
                return _get_authorize_error_response(
                    error, grant.params.get("redirect_uri")
                )

            try:
                get_current_user()
                response = server.create_authorization_response(user)
            except Unauthorized:
                error = AccessDeniedError(
                    state=grant.params.get("state"), uri=grant.params.get("uri")
                )
                return _get_authorize_error_response(
                    error, grant.params.get("redirect_uri")
                )

        if "login" in prompts:
            show_consent_screen = True
            try:
                # Re-AuthN user (kind of).
                # TODO (RR 2018-03-16): this could also include removing active
                # refresh tokens.
                flask.session.clear()

                # For a POST, return the redirect in JSON instead of headers.
                if flask.request.method == "POST":
                    redirect_response = flask.make_response(
                        flask.jsonify({"redirect": response.headers["Location"]})
                    )
                else:
                    redirect_response = flask.make_response(
                        flask.redirect(flask.url_for(".authorize"))
                    )

                clear_cookies(redirect_response)
                return redirect_response
            except Unauthorized:
                error = AccessDeniedError(
                    state=grant.params.get("state"), uri=grant.params.get("uri")
                )
                return _get_authorize_error_response(
                    error, grant.params.get("redirect_uri")
                )

        if "consent" in prompts:
            # show consent screen (which is default behavior so pass)
            pass

        if "select_account" in prompts:
            # allow user to select one of their accounts, we
            # don't support this at the moment
            pass

    if show_consent_screen:
        shown_scopes = scope.split(" ")
        if "openid" in shown_scopes:
            shown_scopes.remove("openid")

        enabled_idps = flask.current_app.config.get("OPENID_CONNECT", {})
        idp_names = []
        for idp, info in enabled_idps.iteritems():
            # prefer name if its there, then just use the key for the provider
            idp_name = info.get("name") or idp.title()
            idp_names.append(idp_name)

        resource_description = [
            SCOPE_DESCRIPTION[s].format(idp_names=" and ".join(idp_names))
            for s in shown_scopes
        ]

        response = flask.render_template(
            "oauthorize.html",
            grant=grant,
            user=user,
            client=client,
            app_name=flask.current_app.config.get("APP_NAME"),
            resource_description=resource_description,
        )

    return response


def _get_authorize_error_response(error, redirect_uri):
    """
    Get error response as defined by OIDC spec.

    Args:
        error (authlib.specs.rfc6749.error.OAuth2Error): Specific Oauth2 error
        redirect_uri (str): Redirection url
    """
    params = error.get_body()
    uri = add_params_to_uri(redirect_uri, params)
    headers = [("Location", uri)]
    response = flask.Response("", status=302, headers=headers)
    return response


@blueprint.route("/token", methods=["POST"])
def get_token(*args, **kwargs):
    """
    Handle exchanging code for and refreshing the access token.

    The operation here is handled entirely by the ``oauth.token_handler``
    decorator, so this function only needs to pass.

    See the OpenAPI documentation for detailed specification, and the OAuth2
    tests for examples of some operation and correct behavior.
    """
    return server.create_token_response()


@blueprint.route("/revoke", methods=["POST"])
def revoke_token():
    """
    Revoke a refresh token.

    If the operation is successful, return an empty response with a 204 status
    code. Otherwise, return error message in JSON with a 400 code.

    Return:
        Tuple[str, int]: JSON response and status code
    """
    return server.create_revocation_response()


@blueprint.route("/errors", methods=["GET"])
def display_error():
    """
    Define the errors endpoint for the OAuth provider.
    """
    return flask.jsonify(flask.request.args)
