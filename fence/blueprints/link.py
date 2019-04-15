import time

import flask
from flask_restful import Resource
from flask_sqlalchemy_session import current_session

from cdislogging import get_logger

from cirrus import GoogleCloudManager
from fence.restful import RestfulApi
from fence.errors import NotFound
from fence.errors import Unauthorized
from fence.errors import UserError

from fence.models import UserGoogleAccount
from fence.models import UserGoogleAccountToProxyGroup
from fence.auth import current_token, get_user_from_claims, validate_request
from fence.auth import require_auth_header
from fence.config import config
from fence.resources.google.utils import (
    get_or_create_proxy_group_id,
    get_default_google_account_expiration,
    get_users_linked_google_email,
    get_linked_google_account_email,
)
from fence.utils import (
    clear_cookies,
    append_query_params,
    get_valid_expiration_from_request,
)

logger = get_logger(__name__)


def make_link_blueprint():
    """
    Return:
        flask.Blueprint: the blueprint used for ``/link`` endpoints
    """
    blueprint = flask.Blueprint("link", __name__)
    blueprint_api = RestfulApi(blueprint)

    if config["ALLOW_GOOGLE_LINKING"]:
        blueprint_api.add_resource(GoogleLinkRedirect, "/google", strict_slashes=False)
        blueprint_api.add_resource(
            GoogleCallback, "/google/callback", strict_slashes=False
        )

    return blueprint


class GoogleLinkRedirect(Resource):
    """
    Endpoint for Google Account linkage to users.

    Linking a google account will add it to user's proxy group for a
    configurable amount of time. During this time, the google account
    will have access to the same resources the user does.
    """

    @require_auth_header({"user"})
    def get(self):
        """
        Link a user's Google Account by running the oauth2 flow with
        Google to AuthN user->Google Account linkage.

        This will obtain user information from the auth token and save off some
        of that into a session so when Google redirects back after authN, we
        can continue to have some user information.

        This will redirect with `error` and `error_description` query params
        if any issues arise.

        Raises:
            UserError: No redirect was provided
        """
        return GoogleLinkRedirect._link_google_account()

    @require_auth_header({"user"})
    def patch(self):
        """
        Extend access of the user's linked Google account.

        This will only succeed if the user already has a linked account.
        """
        return GoogleLinkRedirect._extend_account_expiration()

    @require_auth_header({"user"})
    def delete(self):
        """
        Permanently remove a user's linked Google account. This will first
        remove access of the Google account and then delete the linkage,
        allowing the user to link a different account.

        This will redirect with `error` and `error_description` query params
        if any issues arise.
        """
        return GoogleLinkRedirect._unlink_google_account()

    @staticmethod
    def _link_google_account():
        provided_redirect = flask.request.args.get("redirect")

        if not provided_redirect:
            raise UserError({"error": "No redirect provided."})

        user_id = current_token["sub"]
        google_email = get_users_linked_google_email(user_id)
        proxy_group = get_or_create_proxy_group_id()

        # Set session flag to signify that we're linking and not logging in
        # Save info needed for linking in session since we need to AuthN first
        flask.session["google_link"] = True
        flask.session["user_id"] = user_id
        flask.session["google_proxy_group_id"] = proxy_group
        flask.session["linked_google_email"] = google_email

        if not google_email:
            # save off provided redirect in session and initiate Google AuthN
            flask.session["redirect"] = provided_redirect

            # requested time (in seconds) during which the link will be valid
            requested_expires_in = get_valid_expiration_from_request()
            if requested_expires_in:
                flask.session["google_link_expires_in"] = requested_expires_in

            # if we're mocking Google login, skip to callback
            if config.get("MOCK_GOOGLE_AUTH", False):
                flask.redirect_url = (
                    config["BASE_URL"].strip("/") + "/link/google/callback?code=abc"
                )
                response = flask.redirect(flask.redirect_url)
                # pass-through the authorization header. The user's username
                # MUST be a Google email for MOCK_GOOGLE_AUTH to actually link that
                # email correctly
                response.headers["Authorization"] = flask.request.headers.get(
                    "Authorization"
                )
                return response

            flask.redirect_url = flask.current_app.google_client.get_auth_url()

            # Tell Google to let user select an account
            flask.redirect_url = append_query_params(
                flask.redirect_url, prompt="select_account"
            )
        else:
            # double check that the token isn't stale by hitting db
            linked_email_in_db = get_linked_google_account_email(user_id)

            if linked_email_in_db:
                # skip Google AuthN, already linked, error
                redirect_with_errors = append_query_params(
                    provided_redirect,
                    error="g_acnt_link_error",
                    error_description="User already has a linked Google account.",
                )
                flask.redirect_url = redirect_with_errors
                _clear_google_link_info_from_session()
            else:
                # TODO can we handle this error?
                redirect_with_errors = append_query_params(
                    provided_redirect,
                    error="g_acnt_link_error",
                    error_description="Stale access token, please refresh.",
                )
                flask.redirect_url = redirect_with_errors
                _clear_google_link_info_from_session()

        return flask.redirect(flask.redirect_url)

    @staticmethod
    def _extend_account_expiration():
        user_id = current_token["sub"]
        google_email = get_users_linked_google_email(user_id)
        proxy_group = get_or_create_proxy_group_id()

        # requested time (in seconds) during which the link will be valid
        requested_expires_in = get_valid_expiration_from_request()

        access_expiration = _force_update_user_google_account(
            user_id,
            google_email,
            proxy_group,
            _allow_new=False,
            requested_expires_in=requested_expires_in,
        )

        return {"exp": access_expiration}, 200

    @staticmethod
    def _unlink_google_account():
        user_id = current_token["sub"]

        g_account = (
            current_session.query(UserGoogleAccount)
            .filter(UserGoogleAccount.user_id == user_id)
            .first()
        )

        if not g_account:
            error_message = {
                "error": "g_acnt_link_error",
                "error_description": (
                    "Couldn't unlink account for user, no linked Google "
                    "account found."
                ),
            }
            _clear_google_link_info_from_session()
            return error_message, 404

        g_account_access = (
            current_session.query(UserGoogleAccountToProxyGroup)
            .filter(
                UserGoogleAccountToProxyGroup.user_google_account_id == g_account.id
            )
            .first()
        )

        if g_account_access:
            try:
                with GoogleCloudManager() as g_manager:
                    g_manager.remove_member_from_group(
                        member_email=g_account.email,
                        group_id=g_account_access.proxy_group_id,
                    )
            except Exception as exc:
                error_message = {
                    "error": "g_acnt_access_error",
                    "error_description": (
                        "Couldn't remove account from user's proxy group, "
                        "Google API failure. Exception: {}".format(exc)
                    ),
                }
                _clear_google_link_info_from_session()
                return error_message, 400

            current_session.delete(g_account_access)
            current_session.commit()

        current_session.delete(g_account)
        current_session.commit()

        # clear session and cookies so access token and session don't have
        # outdated linkage info
        flask.session.clear()
        response = flask.make_response("", 200)
        clear_cookies(response)

        return response


class GoogleCallback(Resource):
    def get(self):
        """
        Link a user's Google account after AuthN.

        This is Google's callback that occurs after oauth2 flow and does
        the actual linkage/creation in our db.

        This will redirect with `error` and `error_description` query params
        if any issues arise.

        Raises:
            UserError: No redirect provided
        """
        provided_redirect = flask.session.get("redirect")
        code = flask.request.args.get("code")

        if not config.get("MOCK_GOOGLE_AUTH", False):
            google_response = flask.current_app.google_client.get_user_id(code)
            email = google_response.get("email")
        else:
            # if we're mocking google auth, mock response to include the email
            # from the provided access token
            try:
                token = validate_request({"user"})
                email = get_user_from_claims(token).username
            except Exception as exc:
                logger.info(
                    "Unable to parse Google email from token, using default mock value. "
                    "Error: {}".format(exc)
                )
                email = flask.request.cookies.get(
                    config.get("DEV_LOGIN_COOKIE_NAME"), "test@example.com"
                )

        error = ""
        error_description = ""

        # get info from session and then clear it
        user_id = flask.session.get("user_id")
        proxy_group = flask.session.get("google_proxy_group_id")
        expires_in = flask.session.get("google_link_expires_in")
        _clear_google_link_info_from_session()

        if not email:
            error = "g_acnt_auth_failure"
            error_description = google_response
        else:
            error, error_description = get_errors_update_user_google_account_dry_run(
                user_id, email, proxy_group, _already_authed=True
            )

            if not error:
                exp = _force_update_user_google_account(
                    user_id,
                    email,
                    proxy_group,
                    _allow_new=True,
                    requested_expires_in=expires_in,
                )

                # TODO: perhaps this is problematic??
                # keep linked email in session so when session refreshes access
                # token, we don't have to hit db to see if user has linked acnt
                # NOTE: This only saves us from a db hit if they maintain their
                # session
                flask.session["linked_google_email"] = email

        # if we have a redirect, follow it and add any errors
        if provided_redirect:
            if error:
                redirect_with_params = append_query_params(
                    provided_redirect, error=error, error_description=error_description
                )
            else:
                redirect_with_params = append_query_params(
                    provided_redirect, linked_email=email, exp=exp
                )

            return flask.redirect(redirect_with_params)
        else:
            # we don't have a redirect, so the endpoint was probably hit
            # without the actual auth flow. Raise with error info
            if error:
                raise UserError({error: error_description})
            else:
                raise UserError({"error": "No redirect provided."})


def get_errors_update_user_google_account_dry_run(
    user_id, google_email, proxy_group, _already_authed=False
):
    """
    Gets error and details for attempting to add user's google account to
    proxy group and/or updating expiration for that google account's access.

    NOTE: This is a dry run, it won't actually perform the update.

    NOTE: _already_authed=True means that AUTHENTICATION SHOULD HAVE
         ALREADY OCCURED. That means that we've already verified that the
         google_email belongs to the given user_id.

    For just updating expiration, you can provide _already_authed=False, which
    means that this will NOT allow the creation of a new UserGoogleAccount and
    only update one that already exists.

    Args:
        user_id (TYPE): User's identifier
        google_email (TYPE): User's Google email
        proxy_group (TYPE): User's Proxy Google group
        _already_authed (bool, optional): Whether or not AuthN has happened

    Returns:
        tuple(str, str): ('error', 'error_description') None in the 'error'
            location means there was no error
    """
    error = None
    error_description = None

    user_google_account = (
        current_session.query(UserGoogleAccount)
        .filter(UserGoogleAccount.email == google_email)
        .first()
    )

    if not user_google_account:
        if _already_authed:
            if not user_id:
                error = "g_acnt_link_error"
                error_description = (
                    "Could not determine authed user "
                    "from session. Unable to link Google account."
                )
        else:
            error = "g_acnt_link_error"
            error_description = (
                "User doesn't have a linked Google account. Cannot "
                "extend expiration."
            )
    elif not proxy_group:
        error = "g_acnt_access_error"
        error_description = (
            "No proxy group found for user {}. Could not give Google Account "
            "access. Proxy groups are created automatically on a timed "
            "schedule. Please try again later.".format(user_id)
        )
    else:
        if user_google_account.user_id != user_id:
            error = "g_acnt_link_error"
            error_description = (
                "Could not link Google account. "
                "The account specified is "
                "already linked to a different user."
            )
        else:
            # valid, no errors
            pass

    return (error, error_description)


def _force_update_user_google_account(
    user_id, google_email, proxy_group_id, _allow_new=False, requested_expires_in=None
):
    """
    Adds user's google account to proxy group and/or updates expiration for
    that google account's access.

    WARNING: This assumes that provided arguments represent valid information.
             This BLINDLY adds without verification. Do verification
             before this.

    Specifically, this ASSUMES that the proxy group provided belongs to the
    given user and that the user has ALREADY authenticated to prove the
    provided google_email is also their's.

    Args:
        user_id (str): User's identifier
        google_email (str): User's Google email
        proxy_group_id (str): User's Proxy Google group id
        _allow_new (bool, optional): Whether or not a new linkage between
            Google email and the given user should be allowed
        requested_expires_in (int, optional): Requested time (in seconds)
            during which the link will be valid

    Raises:
        NotFound: Linked Google account not found
        Unauthorized: Couldn't determine user

    Returns:
        Expiration time of the newly updated google account's access
    """
    user_google_account = (
        current_session.query(UserGoogleAccount)
        .filter(UserGoogleAccount.email == google_email)
        .first()
    )

    if not user_google_account:
        if _allow_new:
            if user_id is not None:
                user_google_account = add_new_user_google_account(
                    user_id, google_email, current_session
                )
                logger.info(
                    "Linking Google account {} to user with id {}.".format(
                        google_email, user_id
                    )
                )
            else:
                raise Unauthorized(
                    "Could not determine authed user "
                    "from session. Unable to link Google account."
                )
        else:
            raise NotFound(
                "User does not have a linked Google account. Update "
                "was attempted and failed."
            )

    # timestamp at which the link will expire
    expiration = get_default_google_account_expiration()
    if requested_expires_in:
        requested_expiration = int(time.time()) + requested_expires_in
        expiration = min(requested_expiration, expiration)

    force_update_user_google_account_expiration(
        user_google_account, proxy_group_id, google_email, expiration, current_session
    )

    logger.info(
        "Adding user's (id: {}) Google account to their proxy group (id: {})."
        " Expiration: {}".format(
            user_google_account.user_id, proxy_group_id, expiration
        )
    )

    current_session.commit()

    return expiration


def force_update_user_google_account_expiration(
    user_google_account, proxy_group_id, google_email, expiration, session
):
    """
    Adds user's google account to proxy group and/or updates expiration for
    that google account's access.

    WARNING: This assumes that provided arguments represent valid information.
             This BLINDLY adds without verification. Do verification
             before this.

    Specifically, this ASSUMES that the proxy group provided belongs to the
    given user and that the user has ALREADY authenticated to prove the
    provided google_email is also their's.

    Args:
        user_google_account (str): User's linked Google account
        google_email (str): User's Google email
        proxy_group_id (str): User's Proxy Google group id
        expiration (int): new expiration for User's linked Google account to live in
            the proxy group
        session: db session to work with
    """
    account_in_proxy_group = (
        session.query(UserGoogleAccountToProxyGroup)
        .filter(
            UserGoogleAccountToProxyGroup.user_google_account_id
            == user_google_account.id
        )
        .first()
    )
    if account_in_proxy_group:
        account_in_proxy_group.expires = expiration
    else:
        account_in_proxy_group = UserGoogleAccountToProxyGroup(
            user_google_account_id=user_google_account.id,
            proxy_group_id=proxy_group_id,
            expires=expiration,
        )
        session.add(account_in_proxy_group)

        _add_google_email_to_proxy_group(
            google_email=google_email, proxy_group_id=proxy_group_id
        )


def add_new_user_google_account(user_id, google_email, session):
    user_google_account = UserGoogleAccount(email=google_email, user_id=user_id)
    session.add(user_google_account)
    session.commit()
    return user_google_account


def _add_google_email_to_proxy_group(google_email, proxy_group_id):
    with GoogleCloudManager() as g_manager:
        g_manager.add_member_to_group(
            member_email=google_email, group_id=proxy_group_id
        )


def _clear_google_link_info_from_session():
    # remove google linking info from session
    flask.session.pop("google_link")
    flask.session.pop("user_id")
    flask.session.pop("google_proxy_group_id")
    flask.session.pop("google_link_expires_in")
