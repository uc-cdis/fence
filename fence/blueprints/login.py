import urllib
import flask
from flask import session, redirect, request, jsonify
from flask import current_app as capp
from fence.auth import login_user
from fence.errors import UserError
from fence.data_model.models import IdentityProvider


blueprint = flask.Blueprint('login', __name__)


@blueprint.route('/shib', methods=['GET'])
def login_from_shibboleth():
    redirect_url = request.args.get('redirect')
    return redirect(capp.config['SSO_URL'] + redirect_url)



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
