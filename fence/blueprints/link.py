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

        if not email:
            return flask.redirect(
                flask.session.get('redirect') + '?error=g_acnt_auth_failure' +
                '&error_description=' + result
            )

        user_google_account = (
            current_session.query(UserGoogleAccount)
            .filter(UserGoogleAccount.email == email).first()
        )

        if not user_google_account:
            user_google_account = UserGoogleAccount(
                email=email,
                user_id=flask.session['user_id']
            )
            current_session.add(user_google_account)

            flask.current_app.logger.info(
                'Linking Google account {} to user {}.'.format(
                    email, flask.session['user_id']))

        elif user_google_account.user_id != flask.session['user_id']:
            return flask.redirect(
                flask.session.get('redirect') +
                '?error=g_acnt_link_failure' +
                '&error_description=Could not link Google '
                'account. The account specified is already linked '
                'to a different user.'
            )
        else:
            # we found a google account that belongs to the user
            pass

        try:
            attempt_to_add_user_google_account_to_proxy_group(
                user_google_account, flask.session['google_proxy_group_id'])
        except APIError as error:
            return flask.redirect(
                flask.session.get('redirect') +
                '?error=g_acnt_access_failure' +
                '&error_description=' + error.message
            )

        if flask.session.get('redirect'):
            return flask.redirect(flask.session.get('redirect'))

        return '', 200


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
