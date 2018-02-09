import flask
from flask_restful import Resource

from fence.jwt.validate import require_jwt


class ShibbolethLoginStart(Resource):

    def get(self):
        """
        The login flow is:
        user
        -> {fence}/login/shib?redirect={portal}
        -> user login at {nih_shibboleth_idp}
        -> nih idp POST to fence shibboleth and establish a shibboleth sp
           session
        -> redirect to {fence}/login/shib/login that sets up fence session
        -> redirect to portal
        """
        redirect_url = flask.request.args.get('redirect')
        if redirect_url:
            flask.session['redirect'] = redirect_url
        actual_redirect = (
            flask.current_app.config['HOSTNAME']
            + '/login/shib/login'
        )
        return flask.redirect(
            flask.current_app.config['SSO_URL']
            + actual_redirect
        )


class ShibbolethLoginFinish(Resource):

    @require_jwt({'user'})
    def get(self):
        """
        Complete the shibboleth login.
        """
        if flask.session.get('redirect'):
            return flask.redirect(flask.session.get('redirect'))
        return "logged in"
