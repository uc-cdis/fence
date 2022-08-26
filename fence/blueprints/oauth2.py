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


from authlib.common.urls import add_params_to_uri
from authlib.oauth2.rfc6749 import AccessDeniedError, InvalidRequestError, OAuth2Error
import flask
import json

from authutils.errors import JWTExpiredError

from fence.blueprints.login import get_idp_route_name, get_login_providers_info
from fence.errors import Unauthorized, UserError
from fence.jwt.errors import JWTError
from fence.jwt.token import SCOPE_DESCRIPTION
from fence.models import Client
from fence.oidc.endpoints import RevocationEndpoint
from fence.oidc.server import server
from fence.utils import clear_cookies
from fence.user import get_current_user
from fence.config import config


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
    user = None
    try:
        user = get_current_user()
    except Unauthorized:
        need_authentication = True

    idp = flask.request.args.get("idp")
    fence_idp = flask.request.args.get("fence_idp")
    shib_idp = flask.request.args.get("shib_idp")

    login_url = None
    if not idp:
        if not config.get("DEFAULT_LOGIN_IDP") and "default" not in (
            config.get("ENABLED_IDENTITY_PROVIDERS") or {}
        ):
            # fall back on deprecated DEFAULT_LOGIN_URL
            login_url = config.get("DEFAULT_LOGIN_URL")
        else:
            default_provider_info, _ = get_login_providers_info()
            idp = default_provider_info["idp"]
            # if more than 1 URL is configured, default to the 1st one
            login_url = default_provider_info["urls"][0]["url"]

    if need_authentication or not user:
        redirect_url = config.get("BASE_URL") + flask.request.full_path
        params = {"redirect": redirect_url}

        if not login_url:
            if idp not in config["OPENID_CONNECT"]:
                raise UserError("idp {} is not supported".format(idp))
            idp_endpoint = get_idp_route_name(idp)
            login_url = "{}/login/{}".format(config.get("BASE_URL"), idp_endpoint)

        # handle valid extra params for fence multi-tenant and shib login
        if idp == "fence" and fence_idp:
            params["idp"] = fence_idp
            if fence_idp == "shibboleth":
                params["shib_idp"] = shib_idp
        elif idp == "shibboleth" and shib_idp:
            params["shib_idp"] = shib_idp

        # store client_id for later use in login endpoint prepare_login_log()
        flask.session["client_id"] = flask.request.args.get("client_id")

        login_url = add_params_to_uri(login_url, params)
        return flask.redirect(login_url)

    try:
        grant = server.validate_consent_request(end_user=user)
    except OAuth2Error as e:
        raise Unauthorized("Failed to authorize: {}".format(str(e)))

    client_id = grant.client.client_id
    with flask.current_app.db.session as session:
        client = session.query(Client).filter_by(client_id=client_id).first()

    # TODO: any way to get from grant?
    confirm = flask.request.form.get("confirm") or flask.request.args.get("confirm")
    if client.auto_approve:
        confirm = "yes"
    if confirm is not None:
        response = _handle_consent_confirmation(user, confirm)
        # if it's a 302 for POST confirm, return 200 instead and include
        # redirect url in body because browser ajax POST doesn't follow
        # cross origin redirect
        if flask.request.method == "POST" and response.status_code == 302:
            response = flask.jsonify({"redirect": response.headers["Location"]})
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
        response = server.create_authorization_response(grant_user=user)
    else:
        # user did not give consent
        response = server.create_authorization_response(grant_user=None)
    return response


def _authorize(user, grant, client):
    """
    Return server response when user has not yet provided consent.

    Args:
        user (fence.models.User): authN'd user
        grant (fence.oidc.grants.AuthorizationCodeGrant): request grant
        client (fence.models.Client): request client
    """
    scope = flask.request.args.get("scope")
    response = _get_auth_response_for_prompts(grant.prompt, grant, user, client, scope)
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
        shown_scopes = [] if not scope else scope.split(" ")
        if "openid" in shown_scopes:
            shown_scopes.remove("openid")

        enabled_idps = config.get("OPENID_CONNECT", {})
        idp_names = []
        for idp, info in enabled_idps.items():
            # prefer name if its there, then just use the key for the provider
            idp_name = info.get("name") or idp.title()
            idp_names.append(idp_name)

        resource_description = [
            SCOPE_DESCRIPTION[s].format(idp_names=" and ".join(idp_names))
            for s in shown_scopes
        ]

        privacy_policy = config.get("BASE_URL").rstrip("/") + "/privacy-policy"

        response = flask.render_template(
            "oauthorize.html",
            grant=grant,
            user=user,
            client=client,
            app_name=config.get("APP_NAME"),
            resource_description=resource_description,
            privacy_policy=privacy_policy,
        )

    return response


def _get_authorize_error_response(error, redirect_uri):
    """
    Get error response as defined by OIDC spec.

    Args:
        error (authlib.oauth2.rfc6749.error.OAuth2Error): Specific Oauth2 error
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

    See the OpenAPI documentation for detailed specification, and the OAuth2
    tests for examples of some operation and correct behavior.
    """
    try:
        response = server.create_token_response()
    except (JWTError, JWTExpiredError) as e:
        # - in Authlib 0.11, create_token_response does not raise OAuth2Error
        # - fence.jwt.errors.JWTError: blacklisted refresh token
        # - JWTExpiredError (cdiserrors.AuthNError subclass): expired
        #   refresh token
        # Returns code 400 per OAuth2 spec
        body = {"error": "invalid_grant", "error_description": e.message}
        response = flask.Response(
            json.dumps(body), mimetype="application/json", status=400
        )
    return response


@blueprint.route("/revoke", methods=["POST"])
def revoke_token():
    """
    Revoke a refresh token.

    If the operation is successful, return an empty response with a 204 status
    code. Otherwise, return error message in JSON with a 400 code.

    Return:
        Tuple[str, int]: JSON response and status code
    """
    return server.create_endpoint_response(RevocationEndpoint.ENDPOINT_NAME)


@blueprint.route("/errors", methods=["GET"])
def display_error():
    """
    Define the errors endpoint for the OAuth provider.
    """
    return flask.jsonify(flask.request.args)
