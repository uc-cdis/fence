"""
Create a blueprint with endoints for logins from configured identity providers.

The identity providers include, for example, Google, Shibboleth, or another
fence instance. See the other files in this directory for the definitions of
the endpoints for each provider.
"""

import flask

from fence.blueprints.login.fence_login import FenceLogin, FenceCallback
from fence.blueprints.login.google import GoogleLogin, GoogleCallback
from fence.blueprints.login.shib import ShibbolethLogin, ShibbolethCallback
from fence.blueprints.login.microsoft import MicrosoftLogin, MicrosoftCallback
from fence.blueprints.login.orcid import ORCIDLogin, ORCIDCallback
from fence.blueprints.login.synapse import SynapseLogin, SynapseCallback
from fence.errors import InternalError
from fence.restful import RestfulApi
from fence.config import config

from cdislogging import get_logger

logger = get_logger(__name__)

# Mapping from IDP ID to the name in the URL on the blueprint (see below).
IDP_URL_MAP = {
    "fence": "fence",
    "google": "google",
    "shibboleth": "shib",
    "orcid": "orcid",
    "synapse": "synapse",
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
        if "login_options" in config["ENABLED_IDENTITY_PROVIDERS"]:
            login_options = config["ENABLED_IDENTITY_PROVIDERS"]["login_options"]
        else:
            # fall back on "providers"
            enabled_providers = config["ENABLED_IDENTITY_PROVIDERS"]["providers"]
            login_options = [
                {
                    "name": details["name"],
                    "idp": idp,
                    "desc": details.get("desc"),
                    "secondary": details.get("secondary"),
                }
                for idp, details in enabled_providers.items()
            ]
    except KeyError as e:
        logger.warn(
            "app not configured correctly with ENABLED_IDENTITY_PROVIDERS:"
            " missing {}".format(str(e))
        )
        default_idp = None
        login_options = []

    idps = [login_details["idp"] for login_details in login_options]

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
            # TODO: append idp and shib_idp parameters
            try:
                base_url = config["BASE_URL"].rstrip("/")
                return base_url + "/login/{}".format(IDP_URL_MAP[provider_id])
            except KeyError as e:
                raise InternalError(
                    "identity providers misconfigured: {}".format(str(e))
                )

        def provider_info(login_details):
            info = {
                "id": login_details["idp"],  # deprecated, replaced by "idp"
                "idp": login_details["idp"],
                "name": login_details["name"],
                "url": absolute_login_url(login_details["idp"]),
                "desc": login_details.get("desc", None),
                "secondary": login_details.get("secondary", False),
            }
            if login_details["idp"] == "fence" and "shib_idps" in login_details:
                shib_idps = login_details["shib_idps"]
                if shib_idps == "*":
                    # TODO: get all idps
                    shib_idps = []
                elif not isinstance(shib_idps, list):
                    raise InternalError(
                        'fence provider misconfigured: "shib_idps" must be a list or "*", got {}'.format(
                            shib_idps
                        )
                    )
                info["shib_idps"] = shib_idps
            return info

        all_provider_info = [
            provider_info(login_details) for login_details in login_options
        ]
        # if several login_options are defined for this default IDP, will
        # default to the first one:
        default_provider_info = next(
            (info for info in all_provider_info if info["idp"] == default_idp), None
        )
        if not default_provider_info:
            raise InternalError("default provider misconfigured")

        return flask.jsonify(
            {"default_provider": default_provider_info, "providers": all_provider_info}
        )

    # Add identity provider login routes for IDPs enabled in the config.

    if "fence" in idps:
        blueprint_api.add_resource(FenceLogin, "/fence", strict_slashes=False)
        blueprint_api.add_resource(FenceCallback, "/fence/login", strict_slashes=False)

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

    if "synapse" in idps:
        blueprint_api.add_resource(SynapseLogin, "/synapse", strict_slashes=False)
        blueprint_api.add_resource(
            SynapseCallback, "/synapse/login", strict_slashes=False
        )

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
