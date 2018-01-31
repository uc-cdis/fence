import flask

from fence.auth import login_user, login_required
from fence.errors import UserError
from fence.models import IdentityProvider


blueprint = flask.Blueprint('login', __name__)


@blueprint.route('/shib', methods=['GET'])
def login_from_shibboleth():
    """
    The login flow is: user -> {fence}/login/shib?redirect={portal}
    -> user login at {nih_shibboleth_idp} -> nih idp POST to fence shibboleth
    and establish a shibboleth sp session
    -> redirect to {fence}/login/shib/login that sets up fence session
    -> redirect to portal
    """
    redirect_url = flask.request.args.get('redirect')
    if redirect_url:
        flask.session['redirect'] = redirect_url
    actual_redirect = flask.current_app.config['HOSTNAME'] + '/login/shib/login'
    return flask.redirect(flask.current_app.config['SSO_URL'] + actual_redirect)


@blueprint.route('/shib/login', methods=['GET'])
@login_required({'user'})
def finish_login_from_shib():
    if flask.session.get('redirect'):
        return flask.redirect(flask.session.get('redirect'))
    return "logged in"

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
