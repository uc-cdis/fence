import time

import flask
from flask_restful import Resource
from flask_restful import Api
from flask_sqlalchemy_session import current_session

from fence.errors import UserError
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
        # reset link flask
        flask.session['google_link'] = False
        code = flask.request.args.get('code')
        result = flask.current_app.google_client.get_user_id(code)
        email = result.get('email')
        if email:
            # TODO add to proxy group and stuff
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

                add_account_to_proxy_group = UserGoogleAccountToProxyGroup(
                    user_google_account_id=user_google_account.id,
                    proxy_group_id=flask.session['google_proxy_group_id'],
                    expires=get_default_google_account_expiration()
                )
                current_session.add(add_account_to_proxy_group)
                current_session.commit()

            if flask.session.get('redirect'):
                return flask.redirect(flask.session.get('redirect'))
            return flask.jsonify({'username': email})
        raise UserError(result)


def get_default_google_account_expiration():
    now = int(time.time())
    seconds_in_24_hours = 86400
    expiration = now + seconds_in_24_hours
    return expiration


blueprint_api.add_resource(
    GoogleLinkRedirect, '/google', strict_slashes=False
)
blueprint_api.add_resource(
    GoogleLink, '/google/link', strict_slashes=False
)
