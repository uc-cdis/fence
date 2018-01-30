import urllib
import flask
from flask import session, redirect, request, jsonify
from flask import current_app as capp
from fence.auth import login_user, login_required
from fence.errors import UserError
from fence.data_model.models import IdentityProvider


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
    redirect_url = request.args.get('redirect')
    if redirect_url:
        session['redirect'] = redirect_url
    actual_redirect= capp.config['HOSTNAME'] + '/login/shib/login'
    return redirect(capp.config['SSO_URL'] + actual_redirect)


@blueprint.route('/shib/login', methods=['GET'])
@login_required({'user'})
def finish_login_from_shib():
    if session.get('redirect'):
        return redirect(session.get('redirect'))
    return "logged in"

@blueprint.route('/google', methods=['GET'])
def redirect_to_google():
    redirect_url = request.args.get('redirect')
    if redirect_url:
        session['redirect'] = redirect_url
    return redirect(capp.google_client.get_auth_url())


@blueprint.route('/google/login/', methods=['GET'])
def login_from_google():
    code = request.args.get('code')
    result = capp.google_client.get_user_id(code)
    email = result.get('email')
    if email:
        session['username'] = email
        session['provider'] = IdentityProvider.google
        login_user(request, email, IdentityProvider.google)
        if session.get('redirect'):
            return redirect(session.get('redirect'))
        return jsonify({'username': email})
    raise UserError(result)
