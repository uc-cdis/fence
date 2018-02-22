"""
Create a blueprint with endoints for logins from configured identity providers.

The identity providers include, for example, Google, Shibboleth, or another
fence instance. See the other files in this directory for the definitions of
the endpoints for each provider.
"""

import urlparse

import flask
from flask_restful import Api

from fence.blueprints.login.fence_login import FenceRedirect, FenceLogin
from fence.blueprints.login.google import GoogleRedirect, GoogleLogin
from fence.blueprints.login.shib import (
    ShibbolethLoginStart,
    ShibbolethLoginFinish,
)
from fence.errors import APIError
import fence.settings


if 'default' not in fence.settings.IDENTITY_PROVIDERS:
    raise RuntimeError(
        '`IDENTITY_PROVIDERS` missing `default` field in flask app settings'
    )
if 'providers' not in fence.settings.IDENTITY_PROVIDERS:
    raise RuntimeError(
        '`IDENTITY_PROVIDERS` missing `providers` field in flask app settings'
    )

default_idp = fence.settings.IDENTITY_PROVIDERS['default']
idps = fence.settings.IDENTITY_PROVIDERS['providers']

# Mapping from IDP ID (what goes in ``fence/local_settings.py`` in
# ``IDENTITY_PROVIDERS``) to the name in the URL on the blueprint (see below).
IDP_URL_MAP = {
    'fence': 'fence',
    'google': 'google',
    'shibboleth': 'shib',
}


blueprint = flask.Blueprint('login', __name__)
blueprint_api = Api(blueprint)


@blueprint.route('', methods=['GET'])
def default_login():
    """
    The default root login route.
    """

    def absolute_login_url(provider_id):
        base_url = flask.current_app.config['BASE_URL']
        return urlparse.urljoin(
            base_url, '/login/{}'.format(IDP_URL_MAP[provider_id])
        )

    def provider_info(idp_id):
        return {
            'id': idp_id,
            'name': idps[idp_id]['name'],
            'url': absolute_login_url(idp_id),
        }

    try:
        all_provider_info = [provider_info(idp_id) for idp_id in idps.keys()]
        default_provider_info = provider_info(default_idp)
    except KeyError as e:
        raise APIError('identity providers misconfigured: {}'.format(str(e)))

    return flask.jsonify({
        'default_provider': default_provider_info,
        'providers': all_provider_info,
    })


# Add identity provider login routes for IDPs enabled in the config.

if 'fence' in idps:
    blueprint_api.add_resource(
        FenceRedirect, '/fence', strict_slashes=False
    )
    blueprint_api.add_resource(
        FenceLogin, '/fence/login', strict_slashes=False
    )

if 'google' in idps:
    blueprint_api.add_resource(
        GoogleRedirect, '/google', strict_slashes=False
    )
    blueprint_api.add_resource(
        GoogleLogin, '/google/login', strict_slashes=False
    )

if 'shibboleth' in idps:
    blueprint_api.add_resource(
        ShibbolethLoginStart, '/shib', strict_slashes=False
    )
    blueprint_api.add_resource(
        ShibbolethLoginFinish, '/shib/login', strict_slashes=False
    )
