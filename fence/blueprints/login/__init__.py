"""
Create a blueprint with endoints for logins from configured identity providers.

The identity providers include, for example, Google, Shibboleth, or another
fence instance. See the other files in this directory for the definitions of
the endpoints for each provider.
"""

import flask
from flask_restful import Api

from fence.blueprints.login.fence_login import FenceRedirect, FenceLogin
from fence.blueprints.login.google import GoogleRedirect, GoogleLogin
from fence.blueprints.login.shib import (
    ShibbolethLoginStart,
    ShibbolethLoginFinish,
)
import fence.settings


blueprint = flask.Blueprint('login', __name__)
blueprint_api = Api(blueprint)

enabled_idps = fence.settings.ENABLED_IDENTITY_PROVIDERS

if 'fence' in enabled_idps:
    blueprint_api.add_resource(FenceRedirect, '/fence')
    blueprint_api.add_resource(FenceLogin, '/fence/login')

if 'google' in enabled_idps:
    blueprint_api.add_resource(GoogleRedirect, '/google')
    blueprint_api.add_resource(GoogleLogin, '/google/login')

if 'shibboleth' in enabled_idps:
    blueprint_api.add_resource(ShibbolethLoginStart, '/shib')
    blueprint_api.add_resource(ShibbolethLoginFinish, '/shib/login')
