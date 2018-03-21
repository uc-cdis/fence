import time

import flask
from flask_restful import Resource
from flask_restful import Api
from flask_sqlalchemy_session import current_session

from fence.errors import NotFound
from fence.errors import UserError
from fence.errors import APIError
from fence.models import UserGoogleAccount
from fence.models import UserGoogleAccountToProxyGroup
from fence.auth import current_token
from fence.auth import require_auth_header

blueprint = flask.Blueprint('link', __name__)
blueprint_api = Api(blueprint)


class GoogleLinkRedirect(Resource):

    @require_auth_header({'user'})
    def get(self):
        # Set session flag to signify that we're linking and not logging in
        flask.session['google_link'] = True
        flask.session['user_id'] = current_token['sub']
        flask.session['google_proxy_group_id'] = (
            current_token.get('context', {})
            .get('user', {})
            .get('google', {})
            .get('proxy_group', {})
        )

        flask.redirect_url = flask.request.args.get('redirect')
        if flask.redirect_url:
            flask.session['redirect'] = flask.redirect_url
        return flask.redirect(flask.current_app.google_client.get_auth_url())


class GoogleLink(Resource):

    def get(self):
        code = flask.request.args.get('code')
        result = flask.current_app.google_client.get_user_id(code)
        email = result.get('email')

        error = None
        error_description = None

        if not email:
            error = 'g_acnt_auth_failure'
            error_description = result
        else:
            user_google_account = (
                current_session.query(UserGoogleAccount)
                .filter(UserGoogleAccount.email == email).first()
            )

            if not user_google_account:
                user_id = flask.session.get('user_id')
                if user_id is not None:
                    _add_new_user_google_account(email, user_id)
                else:
                    error = 'unauthorized'
                    error_description = (
                        'Could not determine authed user '
                        'from session. Unable to link Google account.')

            elif user_google_account.user_id != flask.session.get('user_id'):
                error = 'g_acnt_link_failure'
                error_description = (
                    'Could not link Google account. '
                    'The account specified is '
                    'already linked to a different user.')

            else:
                # we found a google account that belongs to the user
                try:
                    attempt_to_add_user_google_account_to_proxy_group(
                        user_google_account,
                        flask.session.get('google_proxy_group_id'))
                except NotFound:
                    error = 'g_acnt_access_failure'
                    error_description = (
                        'No proxy group found for user {}. These are '
                        'created automatically on a timed schedule. Please '
                        'try again later.'
                        .format(flask.session.get('user_id')),
                    )

        # if we have a redirect, follow it and add any errors
        provided_redirect = flask.session.get('redirect')
        _clear_google_link_info_from_session()
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


def _add_new_user_google_account(google_email, user_id):
    user_google_account = UserGoogleAccount(
        email=google_email,
        user_id=user_id
    )
    current_session.add(user_google_account)
    flask.current_app.logger.info(
        'Linking Google account {} to user {}.'.format(
            google_email, user_id))
    current_session.commit()


def _get_error_params(error, description):
    params = ''
    if error:
        params += (
            '?error={}&error_description={}'
            .format(str(error), str(description))
        )
    return params


def _clear_google_link_info_from_session():
    # remove google linking info from session
    flask.session.pop('google_link', None)
    flask.session.pop('user_id', None)
    flask.session.pop('google_proxy_group_id', None)


def get_default_google_account_expiration():
    now = int(time.time())
    seconds_in_24_hours = 86400
    expiration = now + seconds_in_24_hours
    return expiration


def attempt_to_add_user_google_account_to_proxy_group(
        user_google_account, proxy_group_id):
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
        if not proxy_group_id:
            raise NotFound('No proxy group given')

        account_in_proxy_group = UserGoogleAccountToProxyGroup(
            user_google_account_id=user_google_account.id,
            proxy_group_id=proxy_group_id,
            expires=expiration
        )
        current_session.add(account_in_proxy_group)

    flask.current_app.logger.info(
        'Adding user {}\'s Google account to proxy group {}. '
        'Expiration: {}'.format(
            user_google_account,
            proxy_group_id,
            expiration)
    )

    current_session.commit()


blueprint_api.add_resource(
    GoogleLinkRedirect, '/google', strict_slashes=False
)
blueprint_api.add_resource(
    GoogleLink, '/google/link', strict_slashes=False
)
