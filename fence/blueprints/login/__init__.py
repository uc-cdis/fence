"""
Create a blueprint with endpoints for logins from configured identity providers.

We have 2 endpoints for each OIDC provider: a login endpoint and a callback
endpoint. Each endpoint is implemented as a class (and registered as a
blueprint resource).

For generic OIDC implementations, the login and callback classes are created
dynamically by the `createLoginClass` and `createCallbackClass` functions.
They are subclasses of the `DefaultOAuth2Login` and `DefaultOAuth2Callback`
classes; only the provider name and settings differ.

For non-generic OIDC implementations, the login and callback classes are also
subclasses of the `DefaultOAuth2Login` and `DefaultOAuth2Callback` classes,
but the methods may differ to allow for special handling. They must be added
to the codebase at `fence/blueprints/login/` and to the `make_login_blueprint`
function. A client class must also be created at `fence/resources/openid/` and
added to the `_setup_oidc_clients` function. These implementations include,
for example, Google, Shibboleth, or another Fence instance. See the other
files in this directory for the definitions of the endpoints for each
non-generic provider.
"""

from authlib.common.urls import add_params_to_uri
import flask
import requests

from cdislogging import get_logger

from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback
from fence.blueprints.login.cilogon import CilogonLogin, CilogonCallback
from fence.blueprints.login.cognito import CognitoLogin, CognitoCallback
from fence.blueprints.login.fence_login import FenceLogin, FenceCallback
from fence.blueprints.login.google import GoogleLogin, GoogleCallback
from fence.blueprints.login.shib import ShibbolethLogin, ShibbolethCallback
from fence.blueprints.login.microsoft import MicrosoftLogin, MicrosoftCallback
from fence.blueprints.login.okta import OktaLogin, OktaCallback
from fence.blueprints.login.orcid import ORCIDLogin, ORCIDCallback
from fence.blueprints.login.ras import RASLogin, RASCallback
from fence.blueprints.login.synapse import SynapseLogin, SynapseCallback
from fence.errors import InternalError
from fence.resources.audit.utils import enable_audit_logging
from fence.restful import RestfulApi
from fence.config import config

logger = get_logger(__name__)


# Mapping from IDP ID to the name in the URL on the blueprint (see below).
def get_idp_route_name(idp):
    special_routes = {
        "shibboleth": "shib",
    }
    return special_routes.get(idp, idp.lower())


def absolute_login_url(provider_id, fence_idp=None, shib_idp=None):
    """
    Args:
        provider_id (str): provider to log in with.
        fence_idp (str, optional): if provider_id is "fence"
            (multi-tenant Fence setup), fence_idp can be any of the
            providers supported by the other Fence. If not specified,
            will default to NIH login.
        shib_idp (str, optional): if provider_id is "fence" and
            fence_idp is "shibboleth", shib_idp can be any Shibboleth/
            InCommon provider. If not specified, will default to NIH
            login.

    Returns:
        str: login URL for this provider, including extra query
            parameters if fence_idp and/or shib_idp are specified.
    """
    try:
        base_url = config["BASE_URL"].rstrip("/")
        login_url = base_url + "/login/{}".format(get_idp_route_name(provider_id))
    except KeyError as e:
        raise InternalError("identity provider misconfigured: {}".format(str(e)))

    params = {}
    if fence_idp:
        params["idp"] = fence_idp
    if shib_idp:
        params["shib_idp"] = shib_idp
    login_url = add_params_to_uri(login_url, params)

    return login_url


def provider_info(login_details):
    """
    Args:
        login_details (dict):
        { name, desc, idp, fence_idp, shib_idps, secondary }
        - "idp": a configured provider.
        Multiple options can be configured with the same idp.
        - if provider_id is "fence", "fence_idp" can be any of the
        providers supported by the other Fence. If not specified, will
        default to NIH login.
        - if provider_id is "fence" and fence_idp is "shibboleth", a
        list of "shib_idps" can be configured for InCommon login. If
        not specified, will default to NIH login.
        - Optional parameters: "desc" (description) and "secondary"
        (boolean - can be used by the frontend to display secondary
        buttons differently).

    Returns:
        dict: { name, desc, idp, urls, secondary }
        - urls: list of { name, url } dictionaries
    """
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

    # for Fence multi-tenant login
    fence_idp = None
    if login_details["idp"] == "fence":
        fence_idp = login_details.get("fence_idp")

    # handle Shibboleth IDPs: InCommon login can either be configured
    # directly in this Fence, or through multi-tenant Fence
    if (
        login_details["idp"] == "shibboleth" or fence_idp == "shibboleth"
    ) and "shib_idps" in login_details:
        # get list of all available shib IDPs
        if not hasattr(flask.current_app, "all_shib_idps"):
            flask.current_app.all_shib_idps = get_all_shib_idps()

        requested_shib_idps = login_details["shib_idps"]
        if requested_shib_idps == "*":
            shib_idps = flask.current_app.all_shib_idps
        elif isinstance(requested_shib_idps, list):
            # get the display names for each requested shib IDP
            shib_idps = []
            for requested_shib_idp in set(requested_shib_idps):
                shib_idp = next(
                    (
                        available_shib_idp
                        for available_shib_idp in flask.current_app.all_shib_idps
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
                    login_details["idp"], fence_idp, shib_idp["idp"]
                ),
            }
            for shib_idp in shib_idps
        ]

    # non-Shibboleth provider
    else:
        info["urls"] = [
            {
                "name": login_details["name"],
                "url": absolute_login_url(login_details["idp"], fence_idp),
            }
        ]

    return info


def get_login_providers_info():
    # default login option
    if config.get("DEFAULT_LOGIN_IDP"):
        default_idp = config["DEFAULT_LOGIN_IDP"]
    elif "default" in (config.get("ENABLED_IDENTITY_PROVIDERS") or {}):
        # fall back on ENABLED_IDENTITY_PROVIDERS.default
        default_idp = config["ENABLED_IDENTITY_PROVIDERS"]["default"]
    else:
        logger.warning("DEFAULT_LOGIN_IDP not configured")
        default_idp = None

    # other login options
    if config["LOGIN_OPTIONS"]:
        login_options = config["LOGIN_OPTIONS"]
    elif "providers" in (config.get("ENABLED_IDENTITY_PROVIDERS") or {}):
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
        logger.warning("LOGIN_OPTIONS not configured or empty")
        login_options = []

    try:
        all_provider_info = [
            provider_info(login_details) for login_details in login_options
        ]
    except KeyError as e:
        raise InternalError("LOGIN_OPTIONS misconfigured: cannot find key {}".format(e))

    # if several login_options are defined for this default IDP, will
    # default to the first one:
    default_provider_info = next(
        (info for info in all_provider_info if info["idp"] == default_idp), None
    )
    if not default_provider_info:
        raise InternalError(
            "default provider misconfigured: DEFAULT_LOGIN_IDP is set to {}, which is not configured in LOGIN_OPTIONS".format(
                default_idp
            )
        )

    return default_provider_info, all_provider_info


def createLoginClass(idp_name):
    """
    Creates and returns a new class `GenericLogin_<IDP>`, which is a subclass
    of `DefaultOAuth2Login` (only the provider name and settings differ).
    See comment at the top of the file for details.
    """

    def initiate(self):
        super(self.__class__, self).__init__(
            idp_name=idp_name,
            client=getattr(flask.current_app, f"{idp_name}_client"),
        )

    return type(
        f"GenericLogin_{idp_name}",
        (DefaultOAuth2Login,),
        {"__init__": initiate},
    )


def createCallbackClass(idp_name, settings):
    """
    Creates and returns a new class `GenericCallback_<IDP>`, which is a subclass
    of `DefaultOAuth2Callback` (only the provider name and settings differ).
    See comment at the top of the file for details.
    """

    def initiate(self):
        super(self.__class__, self).__init__(
            idp_name=idp_name,
            client=getattr(flask.current_app, f"{idp_name}_client"),
            username_field=settings.get("user_id_field", "sub"),
            email_field=settings.get("email_field", "email"),
            id_from_idp_field=settings.get("id_from_idp_field", "sub"),
        )

    return type(
        f"GenericCallback_{idp_name}",
        (DefaultOAuth2Callback,),
        {"__init__": initiate},
    )


def make_login_blueprint():
    """
    Return:
        flask.Blueprint: the blueprint used for ``/login`` endpoints

    Raises:
        ValueError: if app is not amenably configured
    """

    blueprint = flask.Blueprint("login", __name__)
    blueprint_api = RestfulApi(blueprint, decorators=[enable_audit_logging])

    @blueprint.route("", methods=["GET"])
    def default_login():
        """
        The default root login route.
        """
        default_provider_info, all_provider_info = get_login_providers_info()
        return flask.jsonify(
            {"default_provider": default_provider_info, "providers": all_provider_info}
        )

    # Add identity provider login routes for IDPs enabled in the config.
    configured_idps = config.get("OPENID_CONNECT", {})

    for idp in set(configured_idps.keys()):
        logger.info(f"Setting up login blueprint for {idp}")
        custom_callback_endpoint = None
        if idp == "fence":
            login_class = FenceLogin
            callback_class = FenceCallback
        elif idp == "google":
            login_class = GoogleLogin
            callback_class = GoogleCallback
        elif idp == "orcid":
            login_class = ORCIDLogin
            callback_class = ORCIDCallback
        elif idp == "ras":
            login_class = RASLogin
            callback_class = RASCallback
            # note that the callback endpoint is "/ras/callback", not "/ras/login" like other IDPs
            custom_callback_endpoint = f"/{get_idp_route_name(idp)}/callback"
        elif idp == "synapse":
            login_class = SynapseLogin
            callback_class = SynapseCallback
        elif idp == "microsoft":
            login_class = MicrosoftLogin
            callback_class = MicrosoftCallback
        elif idp == "okta":
            login_class = OktaLogin
            callback_class = OktaCallback
        elif idp == "cognito":
            login_class = CognitoLogin
            callback_class = CognitoCallback
        elif idp == "shibboleth":
            login_class = ShibbolethLogin
            callback_class = ShibbolethCallback
        elif idp == "cilogon":
            login_class = CilogonLogin
            callback_class = CilogonCallback
        else:  # generic OIDC implementation
            login_class = createLoginClass(idp.lower())
            callback_class = createCallbackClass(idp.lower(), configured_idps[idp])

        # create IDP routes
        blueprint_api.add_resource(
            login_class,
            f"/{get_idp_route_name(idp)}",
            strict_slashes=False,
            endpoint=f"{get_idp_route_name(idp)}_login",
        )
        blueprint_api.add_resource(
            callback_class,
            custom_callback_endpoint or f"/{get_idp_route_name(idp)}/login",
            strict_slashes=False,
            endpoint=f"{get_idp_route_name(idp)}_callback",
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

    all_shib_idps = []
    for shib_idp in res.json():
        if "entityID" not in shib_idp:
            logger.warning(
                f"get_all_shib_idps(): 'entityID' field not in IDP data: {shib_idp}. Skipping this IDP."
            )
            continue
        idp = shib_idp["entityID"]
        if len(shib_idp.get("DisplayNames", [])) > 0:
            name = get_shib_idp_en_name(shib_idp["DisplayNames"])
        else:
            logger.warning(
                f"get_all_shib_idps(): 'DisplayNames' field not in IDP data: {shib_idp}. Using IDP ID '{idp}' as IDP name."
            )
            name = idp
        all_shib_idps.append(
            {
                "idp": idp,
                "name": name,
            }
        )
    return all_shib_idps


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
