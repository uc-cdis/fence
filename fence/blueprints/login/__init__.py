"""
Create a blueprint with endoints for logins from configured identity providers.

The identity providers include, for example, Google, Shibboleth, or another
fence instance. See the other files in this directory for the definitions of
the endpoints for each provider.
"""

from cdislogging import get_logger
import flask
import requests

from fence.blueprints.login.fence_login import (
    FenceLogin, FenceCallback, FenceDownstreamIDPs, get_disco_feed
)
from fence.blueprints.login.google import GoogleLogin, GoogleCallback
from fence.blueprints.login.shib import ShibbolethLogin, ShibbolethCallback
from fence.blueprints.login.microsoft import MicrosoftLogin, MicrosoftCallback
from fence.blueprints.login.orcid import ORCIDLogin, ORCIDCallback
from fence.errors import InternalError
from fence.restful import RestfulApi
from fence.config import config

logger = get_logger(__name__)

# Mapping from IDP ID to the name in the URL on the blueprint (see below).
IDP_URL_MAP = {
    "fence": "fence",
    "google": "google",
    "shibboleth": "shib",
    "orcid": "orcid",
    "microsoft": "microsoft",
}


def make_login_blueprint(app):
    """
    Args:
        app (flask.Flask): a flask app (with `app.config` set up)

    Return:
        flask.Blueprint: the blueprint used for ``/login`` endpoints

    Raises:
        ValueError: if app is not amenably configured
    """

    try:
        default_idp = config["ENABLED_IDENTITY_PROVIDERS"]["default"]
        idps = config["ENABLED_IDENTITY_PROVIDERS"]["providers"]
    except KeyError as e:
        logger.warn(
            "app not configured correctly with ENABLED_IDENTITY_PROVIDERS:"
            " missing {}".format(str(e))
        )
        default_idp = None
        idps = {}

    # check if google is configured as a client. we will at least need a
    # a callback if it is
    google_client_exists = (
        "OPENID_CONNECT" in config and "google" in config["OPENID_CONNECT"]
    )

    blueprint = flask.Blueprint("login", __name__)
    blueprint_api = RestfulApi(blueprint)

    @blueprint.route("", methods=["GET"])
    def default_login():
        """
        The default root login route.
        """

        def absolute_login_url(provider_id):
            base_url = config["BASE_URL"].rstrip("/")
            return base_url + "/login/{}".format(IDP_URL_MAP[provider_id])

        def provider_info(idp_id):
            if not idp_id:
                return {"id": None, "name": None, "url": None}
            return {
                "id": idp_id,
                "name": idps[idp_id]["name"],
                "url": absolute_login_url(idp_id),
            }

        try:
            all_provider_info = [provider_info(idp_id) for idp_id in idps.keys()]
            default_provider_info = provider_info(default_idp)
        except KeyError as e:
            raise InternalError("identity providers misconfigured: {}".format(str(e)))

        return flask.jsonify(
            {"default_provider": default_provider_info, "providers": all_provider_info}
        )

    # Add identity provider login routes for IDPs enabled in the config.

    if "fence" in idps:
        blueprint_api.add_resource(FenceLogin, "/fence", strict_slashes=False)
        blueprint_api.add_resource(FenceCallback, "/fence/login", strict_slashes=False)
        fence_idp_url = config["OPENID_CONNECT"].get("fence", {}).get("api_base_url")
        # Check if the fence IDP is a shibboleth provider, in which case we want to add
        # an endpoint on this fence which forwards to the Shibboleth discovery feed
        # endpoint ("DiscoFeed") on the IDP fence.
        if fence_idp_url:
            if get_disco_feed():
                blueprint_api.add_resource(
                    FenceDownstreamIDPs, "/downstream-idps", strict_slashes=False
                )

    if "google" in idps:
        blueprint_api.add_resource(GoogleLogin, "/google", strict_slashes=False)

    # we can use Google Client and callback here without the login endpoint
    # if Google is configured as a client but not in the idps
    if "google" in idps or google_client_exists:
        blueprint_api.add_resource(
            GoogleCallback, "/google/login", strict_slashes=False
        )

    if "orcid" in idps:
        blueprint_api.add_resource(ORCIDLogin, "/orcid", strict_slashes=False)
        blueprint_api.add_resource(ORCIDCallback, "/orcid/login", strict_slashes=False)

    if "microsoft" in idps:
        blueprint_api.add_resource(MicrosoftLogin, "/microsoft", strict_slashes=False)
        blueprint_api.add_resource(
            MicrosoftCallback, "/microsoft/login", strict_slashes=False
        )

    if "shibboleth" in idps:
        blueprint_api.add_resource(ShibbolethLogin, "/shib", strict_slashes=False)
        blueprint_api.add_resource(
            ShibbolethCallback, "/shib/login", strict_slashes=False
        )

    return blueprint
