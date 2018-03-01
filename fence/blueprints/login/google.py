import flask
from flask_restful import Resource

from fence.auth import login_user
from fence.errors import UserError
from fence.models import IdentityProvider


class GoogleRedirect(Resource):

    def get(self):
        flask.redirect_url = flask.request.args.get('redirect')
        if flask.redirect_url:
            flask.session['redirect'] = flask.redirect_url
        return flask.redirect(flask.current_app.google_client.get_auth_url())


class GoogleLogin(Resource):

    def get(self):
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
