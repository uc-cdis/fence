import flask
from flask_restful import Api

from fence.blueprints.login.google import (
    GoogleRedirect,
    GoogleLogin,
)
from fence.blueprints.login.shib import (
    ShibbolethLoginStart,
    ShibbolethLoginFinish,
)


blueprint = flask.Blueprint('login', __name__)
blueprint_api = Api(blueprint)


enabled_idps = flask.current_app.config['ENABLED_IDENTITY_PROVIDERS']


if 'fence' in enabled_idps:
    # TODO
    pass

if 'google' in enabled_idps:
    blueprint_api.add_resource(GoogleRedirect, '/google')
    blueprint_api.add_resource(GoogleLogin, '/google/login')

if 'shibboleth' in enabled_idps:
    blueprint_api.add_resource(ShibbolethLoginStart, '/shib')
    blueprint_api.add_resource(ShibbolethLoginFinish, '/shib/login')
