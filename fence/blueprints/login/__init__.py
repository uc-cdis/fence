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

from cachelib import SimpleCache
from cdislogging import get_logger
import flask
from xml.etree import ElementTree

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
from fence.utils import fetch_url_data

logger = get_logger(__name__)


UPSTREAM_IDP_CACHE = SimpleCache(default_timeout=86400)  # cached for 24h


# Mapping from IDP ID to the name in the URL on the blueprint (see below).
def get_idp_route_name(idp):
    special_routes = {
        "shibboleth": "shib",
    }
    return special_routes.get(idp, idp.lower())


def absolute_login_url(provider_id, upstream_idp=None, shib_idp=None):
    """
    Args:
        provider_id (str): provider to log in with.
        upstream_idp (str, optional): can be set to any of the providers
            supported by the upstream provider (aka provider_id).
            For example, if provider_id is "fence"
            (multi-tenant Fence setup), upstream_idp can be any of the
            providers supported by the other Fence. If not specified,
            will default to NIH login.
        shib_idp (str, optional): if provider_id is "fence" and
            upstream_idp is "shibboleth", shib_idp can be any Shibboleth/
            InCommon provider. If not specified, will default to NIH
            login.

    Returns:
        str: login URL for this provider, including extra query
            parameters if upstream_idp and/or shib_idp are specified.
    """
    try:
        base_url = config["BASE_URL"].rstrip("/")
        login_url = base_url + "/login/{}".format(get_idp_route_name(provider_id))
    except KeyError as e:
        raise InternalError("identity provider misconfigured: {}".format(str(e)))

    params = {}
    if upstream_idp:
        params["idp"] = upstream_idp
    if shib_idp:
        params["shib_idp"] = shib_idp
    login_url = add_params_to_uri(login_url, params)

    return login_url


def get_provider_info(login_details):
    """
    Args:
        login_details (dict):
        { name, desc, idp, upstream_idp, shib_idps, secondary }
        - "idp": a configured provider.
        Multiple options can be configured with the same idp.
        - if provider_id is "fence", "upstream_idp" can be any of the
        providers supported by the other Fence. If not specified, will
        default to NIH login.
        - if provider_id is "fence" and upstream_idp is "shibboleth", a
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
        "url": absolute_login_url(provider_id=login_details["idp"]),
        "desc": login_details.get("desc", None),
        "secondary": login_details.get("secondary", False),
    }

    # for Fence multi-tenant login
    upstream_idp = None
    if login_details["idp"] == "fence":
        # backwards compatibility: fall back to `fence_idp` if `upstream_idp` is not specified
        upstream_idp = login_details.get("upstream_idp", login_details.get("fence_idp"))

    # handle Shibboleth IDPs: InCommon login can either be configured
    # directly in this Fence, or through multi-tenant Fence
    if (
        login_details["idp"] == "shibboleth" or upstream_idp == "shibboleth"
    ) and "shib_idps" in login_details:
        # get list of all available shib IDPs
        if not UPSTREAM_IDP_CACHE.has("all_shib_idps"):
            UPSTREAM_IDP_CACHE.add("all_shib_idps", get_all_shib_idps())

        requested_shib_idps = login_details["shib_idps"]
        if requested_shib_idps == "*":
            shib_idps = UPSTREAM_IDP_CACHE.get("all_shib_idps")
        elif isinstance(requested_shib_idps, list):
            # get the display names for each requested shib IDP
            shib_idps = []
            for requested_shib_idp in set(requested_shib_idps):
                shib_idp = next(
                    (
                        available_shib_idp
                        for available_shib_idp in UPSTREAM_IDP_CACHE.get(
                            "all_shib_idps"
                        )
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
                'login option "{}" misconfigured: "shib_idps" must be a list or "*", got {}'.format(
                    login_details["name"], requested_shib_idps
                )
            )

        info["urls"] = [
            {
                "name": shib_idp["name"],
                "url": absolute_login_url(
                    provider_id=login_details["idp"],
                    upstream_idp=upstream_idp,
                    shib_idp=shib_idp["idp"],
                ),
            }
            for shib_idp in shib_idps
        ]

    # non-Shibboleth provider
    else:
        discovery_details = (
            config["OPENID_CONNECT"]
            .get(login_details["idp"], {})
            .get("idp_discovery", {})
        )
        if discovery_details:
            assert discovery_details.get(
                "url"
            ), f"Unable to get list of {login_details['idp']} IDPs: OPENID_CONNECT.{login_details['idp']}.idp_discovery.url not configured"
            assert discovery_details.get(
                "format"
            ), f"Unable to get list of {login_details['idp']} IDPs: OPENID_CONNECT.{login_details['idp']}.idp_discovery.format not configured"
            cache_key = f"all_{login_details['idp']}_upstream_idps"
            if not UPSTREAM_IDP_CACHE.has(cache_key):
                UPSTREAM_IDP_CACHE.add(
                    cache_key,
                    get_all_upstream_idps(
                        login_details["idp"],
                        discovery_details["url"],
                        discovery_details["format"],
                    ),
                )

            # TODO merge with shib_idps bloc and fallback to shib_idps param
            requested_upstream_idps = login_details.get("upstream_idps")
            if requested_upstream_idps == "*":
                upstream_idps = UPSTREAM_IDP_CACHE.get(cache_key)
            elif isinstance(requested_upstream_idps, list):
                # get the display names for each requested shib IDP
                upstream_idps = []
                for requested_upstream_idp in set(requested_upstream_idps):
                    upstream_idp = next(
                        (
                            available_upstream_idp
                            for available_upstream_idp in UPSTREAM_IDP_CACHE.get(
                                cache_key
                            )
                            if available_upstream_idp["idp"] == requested_upstream_idp
                        ),
                        None,
                    )
                    if not upstream_idp:
                        raise InternalError(
                            'Requested upstream_idp "{}" does not exist'.format(
                                requested_upstream_idp
                            )
                        )
                    upstream_idps.append(upstream_idp)
            else:
                raise InternalError(
                    f'login option "{login_details["name"]}" misconfigured: because "OPENID_CONNECT.{login_details["idp"]}.idp_discovery" is configured, "LOGIN_OPTIONS.{login_details["name"]}.upstream_idps" must be a list or "*", got {requested_upstream_idps}'
                )

            info["urls"] = [
                {
                    "name": upstream_idp["name"],
                    "url": absolute_login_url(
                        provider_id=login_details["idp"],
                        upstream_idp=upstream_idp["idp"],
                    ),
                }
                for upstream_idp in upstream_idps
            ]

        # provider without IdP discovery settings
        else:
            info["urls"] = [
                {
                    "name": login_details["name"],
                    "url": absolute_login_url(
                        provider_id=login_details["idp"], upstream_idp=upstream_idp
                    ),
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
            get_provider_info(login_details) for login_details in login_options
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


# TODO refactor to merge `get_all_upstream_idps` and `get_all_shib_idps`, backwards compatible
# Compared the InCommon list of IDPs with the login.bionimbus.org Shibboleth Discofeed:
# the list of providers is exactly the same (except for the NIH IdP which was removed and replaced
# by us manually from the login.bionimbus.org Discofeed). So we could maybe use the InCommon list
# for everything instead of duplicating the logic.
def get_all_upstream_idps(idp_name: str, discovery_url: str, format: str) -> dict:
    if format == "mdq":  # InCommon Metadata Query Protocol
        all_idps = []
        xml_data = fetch_url_data(discovery_url, "text")
        tree = ElementTree.ElementTree(ElementTree.fromstring(xml_data))
        for element in tree.getroot().iter():
            if element.tag.endswith("EntityDescriptor"):
                if "entityID" not in element.keys():
                    continue
                idp = element.get("entityID")

                # get the IdP's display name
                display_names = []
                for idpsSoDescriptor in element.findall(
                    "{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor"
                ):
                    for extension in idpsSoDescriptor.findall(
                        "{urn:oasis:names:tc:SAML:2.0:metadata}Extensions"
                    ):
                        for uiInfo in extension.findall(
                            "{urn:oasis:names:tc:SAML:metadata:ui}UIInfo"
                        ):
                            for displayName in uiInfo.findall(
                                "{urn:oasis:names:tc:SAML:metadata:ui}DisplayName"
                            ):
                                lang = ""
                                if (
                                    "{http://www.w3.org/XML/1998/namespace}lang"
                                    in displayName.keys()
                                ):
                                    lang = displayName.get(
                                        "{http://www.w3.org/XML/1998/namespace}lang"
                                    )
                                display_names.append(
                                    {"value": displayName.text, "lang": lang}
                                )

                # if IDPSSODescriptor.Extensions.UIInfo.DisplayName is not provided, fall back to
                # Organization.OrganizationDisplayName
                if not display_names:
                    for org in element.findall(
                        "{urn:oasis:names:tc:SAML:2.0:metadata}Organization"
                    ):
                        for orgDisplayName in org.findall(
                            "{urn:oasis:names:tc:SAML:2.0:metadata}OrganizationDisplayName"
                        ):
                            lang = ""
                            if (
                                "{http://www.w3.org/XML/1998/namespace}lang"
                                in orgDisplayName.keys()
                            ):
                                lang = orgDisplayName.get(
                                    "{http://www.w3.org/XML/1998/namespace}lang"
                                )
                            display_names.append(
                                {"value": orgDisplayName.text, "lang": lang}
                            )
                # import json; print(idp, json.dumps(display_names, indent=2))
                all_idps.append(
                    {
                        "idp": idp,
                        "name": get_shib_idp_en_name(display_names)
                        if display_names
                        else idp,
                    }
                )
        return all_idps

    else:
        raise InternalError(
            f"IdP '{idp_name}' misconfigured: idp_discovery.format '{format}' is not supported"
        )


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

    all_shib_idps = []
    for shib_idp in fetch_url_data(url, "json"):
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
