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
        # reset google linking flag
        flask.session['google_link'] = False
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
                _add_new_user_google_account(email, flask.session['user_id'])

            elif user_google_account.user_id != flask.session['user_id']:
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
                        flask.session['google_proxy_group_id'])
                except APIError as error:
                    error = 'g_acnt_access_failure'
                    error_description = error.message

        # if we have a redirect, follow it and add any errors
        if flask.session.get('redirect'):
            error = _get_error_params(error, error_description)
            return flask.redirect(flask.session.get('redirect') + error)
        else:
            # we don't have a redirect, so the endpoint was probably hit
            # without the actual auth flow. Raise with error info
            if error:
                raise APIError({error: error_description})
            else:
                return 'No redirect provided.', 400


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
            raise NotFound(
                'No proxy group found for user {}. These are '
                'created automatically on a timed schedule. Please '
                'try again later.')

        account_in_proxy_group = UserGoogleAccountToProxyGroup(
            user_google_account_id=user_google_account.id,
            proxy_group_id=proxy_group_id,
            expires=expiration
        )
        current_session.add(account_in_proxy_group)

    flask.current_app.logger.info(
        'Adding user {}\'s Google account to proxy group {}. '
        'Expiration: {}'.format(
            flask.session['user_id'],
            flask.session['google_proxy_group_id'],
            expiration)
    )

    current_session.commit()


blueprint_api.add_resource(
    GoogleLinkRedirect, '/google', strict_slashes=False
)
blueprint_api.add_resource(
    GoogleLink, '/google/link', strict_slashes=False
)
