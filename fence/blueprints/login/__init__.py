"""
Create a blueprint with endoints for logins from configured identity providers.

The identity providers include, for example, Google, Shibboleth, or another
fence instance. See the other files in this directory for the definitions of
the endpoints for each provider.
"""

from authlib.common.urls import add_params_to_uri
import flask
import requests

from cdislogging import get_logger

from fence.blueprints.login.fence_login import FenceLogin, FenceCallback
from fence.blueprints.login.google import GoogleLogin, GoogleCallback
from fence.blueprints.login.shib import ShibbolethLogin, ShibbolethCallback
from fence.blueprints.login.microsoft import MicrosoftLogin, MicrosoftCallback
from fence.blueprints.login.orcid import ORCIDLogin, ORCIDCallback
from fence.blueprints.login.synapse import SynapseLogin, SynapseCallback
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

    blueprint = flask.Blueprint("login", __name__)
    blueprint_api = RestfulApi(blueprint)

    @blueprint.route("", methods=["GET"])
    def default_login():
        """
        The default root login route.
        """
        # default login option
        if "DEFAULT_LOGIN_IDP" in config:
            default_idp = config["DEFAULT_LOGIN_IDP"]
        elif "default" in config.get("ENABLED_IDENTITY_PROVIDERS", {}):
            # fall back on ENABLED_IDENTITY_PROVIDERS.default
            default_idp = config["ENABLED_IDENTITY_PROVIDERS"]["default"]
        else:
            logger.warn("DEFAULT_LOGIN_IDP not configured")
            default_idp = None

        # other login options
        if config["LOGIN_OPTIONS"]:
            login_options = config["LOGIN_OPTIONS"]
        elif "providers" in config.get("ENABLED_IDENTITY_PROVIDERS", {}):
            # fall back on "providers" and convert to "login_options" format
            enabled_providers = config["ENABLED_IDENTITY_PROVIDERS"]["providers"]
            login_options = [
                {
                    "name": details.get("name"),
                    "idp": idp,
                    "desc": details.get("desc"),
                    "secondary": details.get("secondary"),
                }
                for idp, details in enabled_providers.items()
            ]
        else:
            logger.warn("LOGIN_OPTIONS not configured or empty")
            login_options = []

        def absolute_login_url(provider_id, shib_idp=None):
            try:
                base_url = config["BASE_URL"].rstrip("/")
                login_url = base_url + "/login/{}".format(IDP_URL_MAP[provider_id])
            except KeyError as e:
                raise InternalError(
                    "identity provider misconfigured: {}".format(str(e))
                )

            if shib_idp:
                login_url = add_params_to_uri(
                    login_url, {"idp": "shibboleth", "shib_idp": shib_idp}
                )
            return login_url

        def provider_info(login_details):
            info = {
                # "id" deprecated, replaced by "idp"
                "id": login_details["idp"],
                "idp": login_details["idp"],
                "name": login_details["name"],
                # "url" deprecated, replaced by "urls"
                "url": absolute_login_url(login_details["idp"]),
                "desc": login_details.get("desc", None),
                "secondary": login_details.get("secondary", False),
            }

            # handle Shibboleth IDPs
            if login_details["idp"] == "fence" and "shib_idps" in login_details:

                # get list of all available shib IDPs
                if not hasattr(app, "all_shib_idps"):
                    app.all_shib_idps = get_all_shib_idps()

                requested_shib_idps = login_details["shib_idps"]
                if requested_shib_idps == "*":
                    shib_idps = app.all_shib_idps
                elif isinstance(requested_shib_idps, list):
                    # get the display names for each requested shib IDP
                    shib_idps = []
                    for requested_shib_idp in requested_shib_idps:
                        shib_idp = next(
                            (
                                available_shib_idp
                                for available_shib_idp in app.all_shib_idps
                                if available_shib_idp["idp"] == requested_shib_idp
                            ),
                            None,
                        )
                        if not shib_idp:
                            raise InternalError(
                                'Requested shib_idp "{}" does not exist'.format(
                                    requested_shib_idp
                                )
                            )
                        shib_idps.append(shib_idp)
                else:
                    raise InternalError(
                        'fence provider misconfigured: "shib_idps" must be a list or "*", got {}'.format(
                            requested_shib_idps
                        )
                    )

                info["urls"] = [
                    {
                        "name": shib_idp["name"],
                        "url": absolute_login_url(
                            login_details["idp"], shib_idp["idp"]
                        ),
                    }
                    for shib_idp in shib_idps
                ]

            # non-Shibboleth provider
            else:
                info["urls"] = [
                    {
                        "name": login_details["name"],
                        "url": absolute_login_url(login_details["idp"]),
                    }
                ]

            return info

        try:
            all_provider_info = [
                provider_info(login_details) for login_details in login_options
            ]
        except KeyError as e:
            raise InternalError("login options misconfigured: {}".format(e))

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
    configured_idps = config["OPENID_CONNECT"].keys()

    if "fence" in configured_idps:
        blueprint_api.add_resource(FenceLogin, "/fence", strict_slashes=False)
        blueprint_api.add_resource(FenceCallback, "/fence/login", strict_slashes=False)

    if "google" in configured_idps:
        blueprint_api.add_resource(GoogleLogin, "/google", strict_slashes=False)
        blueprint_api.add_resource(
            GoogleCallback, "/google/login", strict_slashes=False
        )

    if "orcid" in configured_idps:
        blueprint_api.add_resource(ORCIDLogin, "/orcid", strict_slashes=False)
        blueprint_api.add_resource(ORCIDCallback, "/orcid/login", strict_slashes=False)

    if "synapse" in configured_idps:
        blueprint_api.add_resource(SynapseLogin, "/synapse", strict_slashes=False)
        blueprint_api.add_resource(
            SynapseCallback, "/synapse/login", strict_slashes=False
        )

    if "microsoft" in configured_idps:
        blueprint_api.add_resource(MicrosoftLogin, "/microsoft", strict_slashes=False)
        blueprint_api.add_resource(
            MicrosoftCallback, "/microsoft/login", strict_slashes=False
        )

    if "shibboleth" in configured_idps:
        blueprint_api.add_resource(ShibbolethLogin, "/shib", strict_slashes=False)
        blueprint_api.add_resource(
            ShibbolethCallback, "/shib/login", strict_slashes=False
        )
    return blueprint


def get_all_shib_idps():
    """
    Get the list of all existing Shibboleth IDPs.
    This function only returns the information we need to generate login URLs.

    Returns:
        list: list of {"idp": "", "name": ""} dictionaries
    """
    url = config["OPENID_CONNECT"].get("fence", {}).get("shibboleth_discovery_url")
    if not url:
        raise InternalError(
            "Unable to get list of Shibboleth IDPs: OPENID_CONNECT.fence.shibboleth_discovery_url not configured"
        )
    res = requests.get(url)
    assert (
        res.status_code == 200
    ), "Unable to get list of Shibboleth IDPs from {}".format(url)
    return [
        {
            "idp": shib_idp["entityID"],
            "name": get_shib_idp_en_name(shib_idp["DisplayNames"]),
        }
        for shib_idp in res.json()
    ]


def get_shib_idp_en_name(names):
    """
    Returns a name in English for a Shibboleth IDP, or the first available
    name if no English name was provided.

    Args:
        names (list): list of {"lang": "", "value": ""} dictionaries
            Example:
            [
                {
                    "value": "University of Chicago",
                    "lang": "en"
                },
                {
                    "value": "Universidad de Chicago",
                    "lang": "es"
                }
            ]

    Returns:
        str: Display name to use for this Shibboleth IDP
    """
    for name in names:
        if name.get("lang") == "en":
            return name["value"]
    return names[0]["value"]
