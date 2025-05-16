from urllib.parse import urlencode

from fence.config import config
from fence.blueprints.login import get_all_upstream_idps, UPSTREAM_IDP_CACHE


def test_get_all_upstream_idps(get_all_upstream_idps_mqd_data_patcher):
    """
    Check that `get_all_upstream_idps` parses the XML MDQ data at
    `tests/data/incommon_mdq_data_extract.xml` as expected.
    """
    res = get_all_upstream_idps(
        "generic_mdq_discovery", "https://generic_mdq_discovery/get-all-idps", "mdq"
    )
    assert res == [
        {"idp": "urn:mace:incommon:osu.edu", "name": "Ohio State University"},
        {"idp": "urn:mace:incommon:uchicago.edu", "name": "University of Chicago"},
        {
            # example of choosing the 1st provided value when the display name is not
            # available in English
            "idp": "https://idp.uca.fr/idp/shibboleth",
            "name": "Université Clermont Auvergne",
        },
        {"idp": "urn:mace:incommon:nmu.edu", "name": "Northern Michigan University"},
        {
            "idp": "https://login.restena.lu/simplesamlphp/saml2/idp/metadata.php",
            "name": "RESTENA Users",
        },
        {
            # example of falling back on OrganizationDisplayName because DisplayName
            # is not provided,
            # and example of choosing English when the display name is available in
            # multiple languages including English
            "idp": "https://idp-proxy.ugd.edu.mk",
            "name": "Goce Delcev University, Stip",
        },
    ]


def test_default_login(
    app, client, get_all_shib_idps_patcher, get_all_upstream_idps_mqd_data_patcher
):
    r = client.get("/login")
    assert r.status_code == 200, r.data
    response_json = r.json
    assert "default_provider" in response_json
    response_default = response_json["default_provider"]
    configured_logins = config["LOGIN_OPTIONS"]
    default_idp = config["DEFAULT_LOGIN_IDP"]

    # Check default IDP is correct.
    assert response_default["idp"] == default_idp
    names_for_this_idp = [
        login_details["name"]
        for login_details in configured_logins
        if login_details["idp"] == default_idp
    ]
    assert response_default["name"] in names_for_this_idp


def test_enabled_logins(
    app, client, get_all_shib_idps_patcher, get_all_upstream_idps_mqd_data_patcher
):
    r = client.get("/login")
    assert r.status_code == 200, r.data
    response_json = r.json
    assert "providers" in response_json
    response_providers = response_json["providers"]
    configured_logins = config["LOGIN_OPTIONS"]

    # Check all providers in the response have the expected idp, name, URLs,
    # desc and secondary information
    for configured in configured_logins:
        # this assumes (idp, name) couples in test config are unique
        response_provider = next(
            (
                provider
                for provider in response_providers
                if provider["idp"] == configured["idp"]
                and provider["name"] == configured["name"]
            ),
            None,
        )
        assert (
            response_provider
        ), 'Configured login option "{}" not in /login response: {}'.format()
        if "desc" in configured:
            assert response_provider["desc"] == configured["desc"]
        if "secondary" in configured:
            assert response_provider["secondary"] == configured["secondary"]
        if "upstream_idps" in configured or "shib_idps" in configured:
            # check `upstream_idps`, fallback to `shib_idps`. Handle "*" which means "all IdPs".
            configured_upstream_idps = configured.get(
                "upstream_idps", configured.get("shib_idps")
            )
            if configured_upstream_idps == "*":
                # UPSTREAM_IDP_CACHE should be populated during `client.get("/login")`
                configured_upstream_idps = UPSTREAM_IDP_CACHE.get(
                    f"all_{configured['idp']}_upstream_idps"
                )
                configured_upstream_idps = [
                    idp["idp"] for idp in configured_upstream_idps
                ]

            # each IdP in the configured "upstream_idps" should have a corresponding URL in the
            # list of IdP URLs returned by the /login endpoint
            for upstream_idp in configured_upstream_idps:
                assert any(
                    urlencode({"idp": upstream_idp}) in url_info["url"]
                    for url_info in response_provider["urls"]
                ), 'IdP "{}": upstream_idp param "{}", encoded "{}", is not in provider\'s login URLs: {}'.format(
                    configured["name"],
                    upstream_idp,
                    urlencode({"idp": upstream_idp}),
                    response_provider["urls"],
                )

            # the /login endpoint should only return URLs for IdPs configured in "upstream_idps"
            login_urls = [url_info["url"] for url_info in response_provider["urls"]]
            if configured_upstream_idps:
                assert len(configured_upstream_idps) == len(
                    login_urls
                ), f"URL mismatch for IdP '{configured['name']}'"

        # all IdP URLs returned by the /login endpoint should match an existing app URL
        app_urls = [url_map_rule.rule for url_map_rule in app.url_map._rules]
        login_urls = [
            url_info["url"].replace(config["BASE_URL"], "").split("?")[0]
            for url_info in response_provider["urls"]
        ]
        assert all(url in app_urls for url in login_urls)
