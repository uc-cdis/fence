import time

import flask
import urllib

from flask_restful import Resource
from flask_sqlalchemy_session import current_session

from cirrus import GoogleCloudManager
from fence.restful import RestfulApi
from fence.errors import NotFound
from fence.errors import Unauthorized
from fence.errors import UserError

from fence.models import UserGoogleAccount
from fence.models import UserGoogleAccountToProxyGroup
from fence.auth import current_token
from fence.auth import require_auth_header


def make_link_blueprint():
    """
    Return:
        flask.Blueprint: the blueprint used for ``/link`` endpoints
    """
    blueprint = flask.Blueprint('link', __name__)
    blueprint_api = RestfulApi(blueprint)

    blueprint_api.add_resource(
        GoogleLinkRedirect, '/google', strict_slashes=False
    )
    blueprint_api.add_resource(
        GoogleCallback, '/google/callback', strict_slashes=False
    )

    return blueprint


class GoogleLinkRedirect(Resource):
    """
    Endpoint for Google Account linkage to users.

    Linking a google account will add it to user's proxy group for a
    configurable amount of time. During this time, the google account
    will have access to the same resources the user does.
    """

    @require_auth_header({'user'})
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

    @require_auth_header({'user'})
    def patch(self):
        """
        Extend access of the user's linked Google account.

        This will only succeed if the user already has a linked account.
        """
        return GoogleLinkRedirect._extend_account_expiration()

    @require_auth_header({'user'})
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
        provided_redirect = flask.request.args.get('redirect')

        if not provided_redirect:
            raise UserError({'error': 'No redirect provided.'})

        user_id = current_token['sub']
        google_email = get_users_linked_google_email(user_id)
        proxy_group = get_users_proxy_group_from_token()

        # Set session flag to signify that we're linking and not logging in
        # Save info needed for linking in session since we need to AuthN first
        flask.session['google_link'] = True
        flask.session['user_id'] = user_id
        flask.session['google_proxy_group_id'] = proxy_group
        flask.session['linked_google_email'] = google_email

        if not google_email:
            # save off provided redirect in session and initiate Google AuthN
            flask.session['redirect'] = provided_redirect
            flask.redirect_url = flask.current_app.google_client.get_auth_url()
        else:
            # skip Google AuthN, already linked, error
            error = _get_error_params(
                'g_acnt_link_error',
                'User already has a linked Google account.')
            flask.redirect_url = provided_redirect + error

        return flask.redirect(flask.redirect_url)

    @staticmethod
    def _extend_account_expiration():
        user_id = current_token['sub']
        google_email = get_users_linked_google_email(user_id)
        proxy_group = get_users_proxy_group_from_token()

        _force_update_user_google_account(
            user_id, google_email, proxy_group, _allow_new=False)

        return '', 200

    @staticmethod
    def _unlink_google_account():
        user_id = current_token['sub']

        g_account = (
            current_session.query(UserGoogleAccount)
            .filter(UserGoogleAccount.user_id == user_id).first()
        )

        if not g_account:
            error_message = {
                'error': 'g_acnt_link_error',
                'error_description': (
                    'Couldn\'t unlink account for user, no linked Google '
                    'account found.'
                )
            }
            return error_message, 404

        g_account_access = (
            current_session.query(UserGoogleAccountToProxyGroup)
            .filter(
                UserGoogleAccountToProxyGroup
                .user_google_account_id == g_account.id).first()
        )

        if g_account_access:
            try:
                with GoogleCloudManager() as g_manager:
                    g_manager.remove_member_from_group(
                        member_email=g_account.email,
                        group_id=g_account_access.proxy_group_id
                    )
            except Exception as exc:
                error_message = {
                    'error': 'g_acnt_access_error',
                    'error_description': (
                        'Couldn\'t remove account from user\'s proxy group, '
                        'Google API failure. Exception: {}'.format(exc)
                    )
                }
                return error_message, 400

            current_session.delete(g_account_access)
            current_session.commit()

        current_session.delete(g_account)
        current_session.commit()

        return '', 200


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
        provided_redirect = flask.session.get('redirect')
        code = flask.request.args.get('code')

        google_reponse = flask.current_app.google_client.get_user_id(code)
        email = google_reponse.get('email')

        error = ''
        error_description = ''

        if not email:
            error = 'g_acnt_auth_failure'
            error_description = google_reponse
        else:
            user_id = flask.session.get('user_id')
            proxy_group = flask.session.get('google_proxy_group_id')
            _clear_google_link_info_from_session()

            error, error_description = (
                get_errors_update_user_google_account_dry_run(
                    user_id, email, proxy_group, _already_authed=True)
            )

            if not error:
                _force_update_user_google_account(
                    user_id, email, proxy_group, _allow_new=True)

                # keep linked email in session so when session refreshes access
                # token, we don't have to hit db to see if user has linked acnt
                # NOTE: This only saves us from a db hit if they maintain their
                # session
                flask.session['linked_google_email'] = email

        # if we have a redirect, follow it and add any errors
        if provided_redirect:
            error = _get_error_params(error, error_description)
            return flask.redirect(provided_redirect + error)
        else:
            # we don't have a redirect, so the endpoint was probably hit
            # without the actual auth flow. Raise with error info
            if error:
                raise UserError({error: error_description})
            else:
                raise UserError({'error': 'No redirect provided.'})


def get_errors_update_user_google_account_dry_run(
        user_id, google_email, proxy_group, _already_authed=False):
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
        .filter(UserGoogleAccount.email == google_email).first()
    )

    if not user_google_account:
        if _already_authed:
            if not user_id:
                error = 'g_acnt_link_error'
                error_description = (
                    'Could not determine authed user '
                    'from session. Unable to link Google account.')
        else:
            error = 'g_acnt_link_error'
            error_description = (
                'User doesn\'t have a linked Google account. Cannot '
                'extend expiration.')
    elif not proxy_group:
        error = 'g_acnt_access_error'
        error_description = (
            'No proxy group found for user {}. Could not give Google Account '
            'access. Proxy groups are created automatically on a timed '
            'schedule. Please try again later.'
            .format(user_id)
        )
    else:
        if user_google_account.user_id != user_id:
            error = 'g_acnt_link_error'
            error_description = (
                'Could not link Google account. '
                'The account specified is '
                'already linked to a different user.')
        else:
            # valid, no errors
            pass

    return (error, error_description)


def _force_update_user_google_account(
        user_id, google_email, proxy_group_id, _allow_new=False):
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
        user_id (TYPE): User's identifier
        google_email (TYPE): User's Google email
        proxy_group (TYPE): User's Proxy Google group
        _allow_new (bool, optional): Whether or not a new linkage between
            Google email and the given user should be allowed

    Raises:
        NotFound: Linked Google account not found
        Unauthorized: Couldn't determine user
    """
    user_google_account = (
        current_session.query(UserGoogleAccount)
        .filter(UserGoogleAccount.email == google_email).first()
    )

    if not user_google_account:
        if _allow_new:
            if user_id is not None:
                user_google_account = (
                    _add_new_user_google_account(user_id, google_email))
            else:
                raise Unauthorized(
                    'Could not determine authed user '
                    'from session. Unable to link Google account.')
        else:
            raise NotFound(
                'User does not have a linked Google account. Update '
                'was attempted and failed.')

    expiration = get_default_google_account_expiration()
    account_in_proxy_group = (
        current_session.query(UserGoogleAccountToProxyGroup)
        .filter(
            UserGoogleAccountToProxyGroup.user_google_account_id
            == user_google_account.id
        ).first()
    )
    if account_in_proxy_group:
        account_in_proxy_group.expires = expiration
    else:
        account_in_proxy_group = UserGoogleAccountToProxyGroup(
            user_google_account_id=user_google_account.id,
            proxy_group_id=proxy_group_id,
            expires=expiration
        )
        current_session.add(account_in_proxy_group)

        _add_google_email_to_proxy_group(
            google_email=google_email, proxy_group_id=proxy_group_id)

    flask.current_app.logger.info(
        'Adding user\'s (id: {}) Google account to their proxy group (id: {}).'
        ' Expiration: {}'.format(
            user_google_account.user_id,
            proxy_group_id,
            expiration)
    )

    current_session.commit()


def get_default_google_account_expiration():
    now = int(time.time())
    expiration = (
        now + flask.current_app.config['GOOGLE_ACCOUNT_ACCESS_EXPIRES_IN']
    )
    return expiration


def get_users_linked_google_email(user_id):
    """
    Return user's linked google account's email.
    """
    google_email = get_users_linked_google_email_from_token()
    if not google_email:
        # hit db to check for google_email if it's not in token.
        # this will catch cases where the linking happened during the life
        # of an access token and the same access token is used here (e.g.
        # account exists but a new token hasn't been generated with the linkage
        # info yet)
        google_email = get_users_linked_google_email_from_db(user_id)
    return google_email


def get_users_linked_google_email_from_db(user_id):
    """
    Hit db to check for google_email of user
    """
    google_email = None
    if user_id:
        g_account = (
            current_session.query(UserGoogleAccount)
            .filter(UserGoogleAccount.user_id == user_id).first()
        )
        if g_account:
            google_email = g_account.email
    return google_email


def get_users_linked_google_email_from_token():
    """
    Return a user's linked Google Account's email address by parsing the
    JWT token in the header.

    Returns:
        str: email address of account or None
    """
    return (
        current_token.get('context', {})
        .get('user', {})
        .get('google', {})
        .get('linked_google_account', None)
    )


def get_users_proxy_group_from_token():
    """
    Return a user's proxy group ID by parsing the
    JWT token in the header.

    Returns:
        str: proxy group ID or None
    """
    return (
        current_token.get('context', {})
        .get('user', {})
        .get('google', {})
        .get('proxy_group', None)
    )


def _add_new_user_google_account(user_id, google_email):
    user_google_account = UserGoogleAccount(
        email=google_email,
        user_id=user_id
    )
    current_session.add(user_google_account)
    flask.current_app.logger.info(
        'Linking Google account {} to user with id {}.'.format(
            google_email, user_id))
    current_session.commit()
    return user_google_account


def _get_error_params(error, description):
    params = ''
    if error:
        args = {'error': error, 'error_description': description}
        params = '?' + urllib.urlencode(args)
    return params


def _add_google_email_to_proxy_group(google_email, proxy_group_id):
    with GoogleCloudManager() as g_manager:
        g_manager.add_member_to_group(
            member_email=google_email, group_id=proxy_group_id)


def _clear_google_link_info_from_session():
    # remove google linking info from session
    flask.session.pop('google_link', None)
    flask.session.pop('user_id', None)
    flask.session.pop('google_proxy_group_id', None)
