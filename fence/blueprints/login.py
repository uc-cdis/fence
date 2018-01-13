import urllib

import flask

from fence.auth import login_user
from fence.errors import UserError
from fence.models import IdentityProvider


blueprint = flask.Blueprint('login', __name__)


@blueprint.route('/shib', methods=['GET'])
def login_from_shibboleth():
    return flask.redirect(
        flask.current_app.config['SSO_URL']
        + urllib.quote_plus(flask.request.url)
    )


@blueprint.route('/google', methods=['GET'])
def redirect_to_google():
    flask.redirect_url = flask.request.args.get('redirect')
    if flask.redirect_url:
        flask.session['redirect'] = flask.redirect_url
    return flask.redirect(flask.current_app.google_client.get_auth_url())


@blueprint.route('/google/login/', methods=['GET'])
def login_from_google():
    code = flask.request.args.get('code')
    result = flask.current_app.google_client.get_user_id(code)
    email = result.get('email')
    if email:
        flask.session['username'] = email
        flask.session['provider'] = IdentityProvider.google
        login_user(flask.request, email, IdentityProvider.google)
        if flask.session.get('redirect'):
            return flask.redirect(flask.session.get('redirect'))
        return flask.jsonify({'username': email})
    raise UserError(result)
