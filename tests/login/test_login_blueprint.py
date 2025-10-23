from urllib.parse import urlencode

import pytest

from fence.config import config
from fence.blueprints.login import get_all_upstream_idps, UPSTREAM_IDP_CACHE


def test_get_all_upstream_idps(get_all_upstream_idps_data_patcher):
    """
    Check that `get_all_upstream_idps` parses the XML MDQ data at
    `tests/data/incommon_mdq_data_extract.xml` as expected.
    """
    res = get_all_upstream_idps(
        "generic_mdq_discovery",
        "https://generic_mdq_discovery/get-all-idps",
        "xml-mdq-v1.0",
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


def test_default_login(app, client, get_all_upstream_idps_data_patcher):
    r = client.get("/login")
    assert r.status_code == 200, r.data
    response_json = r.json
    assert "default_provider" in response_json
    response_default = response_json["default_provider"]
    configured_logins = config["LOGIN_OPTIONS"]
    default_idp = config["DEFAULT_LOGIN_IDP"]

    # Check default IdP is correct.
    assert response_default["idp"] == default_idp
    names_for_this_idp = [
        login_details["name"]
        for login_details in configured_logins
        if login_details["idp"] == default_idp
    ]
    assert response_default["name"] in names_for_this_idp


@pytest.mark.parametrize(
    "login_option",
    [
        pytest.param(login_option, id=login_option["name"])
        for login_option in config["LOGIN_OPTIONS"]
    ],
)
def test_enabled_logins(app, client, login_option, get_all_upstream_idps_data_patcher):
    r = client.get("/login")
    assert r.status_code == 200, r.data
    response_json = r.json
    assert "providers" in response_json
    response_providers = response_json["providers"]

    # Check all providers in the response have the expected idp, name, URLs,
    # description and secondary information
    response_provider = next(
        (
            # this assumes (idp, name) couples in test config are unique
            provider
            for provider in response_providers
            if provider["idp"] == login_option["idp"]
            and provider["name"] == login_option["name"]
        ),
        None,
    )
    assert (
        response_provider
    ), 'Configured login option "{}" not in /login response: {}'.format()
    if "desc" in login_option:
        assert response_provider["desc"] == login_option["desc"]
    if "secondary" in login_option:
        assert response_provider["secondary"] == login_option["secondary"]
    if "upstream_idps" in login_option or "shib_idps" in login_option:
        # check `upstream_idps`, fallback to `shib_idps`. Handle "*" which means "all IdPs".
        login_option_upstream_idps = login_option.get(
            "upstream_idps", login_option.get("shib_idps")
        )
        if login_option_upstream_idps == "*":
            # UPSTREAM_IDP_CACHE should have been populated during `client.get("/login")`
            login_option_upstream_idps = [
                idp["idp"]
                for idp in UPSTREAM_IDP_CACHE.get(
                    f"all_{login_option['idp']}_upstream_idps"
                )
                or []
            ]

        # each IdP in the login_option "upstream_idps" should have a corresponding URL in the
        # list of IdP URLs returned by the /login endpoint
        login_urls = [url_info["url"] for url_info in response_provider["urls"]]
        for upstream_idp in login_option_upstream_idps:
            assert any(
                urlencode({"idp": upstream_idp}) in url for url in login_urls
            ), 'IdP "{}": upstream_idp param "{}", encoded "{}", is not in provider\'s login URLs: {}'.format(
                login_option["name"],
                upstream_idp,
                urlencode({"idp": upstream_idp}),
                response_provider["urls"],
            )

        # the /login endpoint should only return URLs for IdPs configured as "upstream_idps"
        if login_option_upstream_idps:
            assert len(login_option_upstream_idps) == len(
                login_urls
            ), f"URL mismatch for IdP '{login_option['name']}'"

    # all IdP URLs returned by the /login endpoint should match an existing app route
    app_routes = [url_map_rule.rule for url_map_rule in app.url_map._rules]
    login_urls = {
        url_info["url"].replace(config["BASE_URL"], "").split("?")[0]
        for url_info in response_provider["urls"]
    }
    assert all(url in app_routes for url in login_urls)


@pytest.mark.parametrize(
    "description, target_provider, hide_idps, expected_hidden_names",
    [
        (
            "Provider with shib_idps=*",
            "MDQ discovery all providers",
            ["https://idp.uca.fr/idp/shibboleth", "urn:mace:incommon:osu.edu"],
            ["Université Clermont Auvergne", "Ohio State University"],
        ),
        (
            "Provider with shib_idps=[list_values]",
            "Shibboleth Login some providers",
            ["urn:mace:incommon:uchicago.edu"],
            ["University of Chicago"],
        ),
        (
            "hide_idps value not in provider shib_idps",
            "Shibboleth Login some providers",
            ["https://idp-proxy.ugd.edu.mk"],
            [],
        ),
    ],
)
def test_hide_idps_logins(
    app,
    client,
    description,
    target_provider,
    hide_idps,
    expected_hidden_names,
    get_all_upstream_idps_data_patcher,
):

    # Start with empty HIDE_IDPS in config
    config["HIDE_IDPS"] = []
    r = client.get("/login")

    assert r.status_code == 200, r.data
    response_json = r.json
    assert "providers" in response_json
    response_providers = response_json["providers"]
    response_provider = next(
        (
            provider
            for provider in response_providers
            if provider["name"] == target_provider
        ),
        None,
    )
    assert (
        response_provider
    ), 'Configured login option "{}" not in /login response: {}'.format()
    all_names = [x["name"] for x in response_provider["urls"]]
    length_no_hides = len(all_names)
    # expected length depends on patcher values.
    assert length_no_hides >= 2, "Provider name list is shorter than expected"
    assert all(name in all_names for name in expected_hidden_names)

    # set HIDE_IDPS in config
    config["HIDE_IDPS"] = hide_idps
    r = client.get("/login")

    assert r.status_code == 200, r.data
    response_json = r.json
    assert "providers" in response_json
    response_providers = response_json["providers"]
    response_provider = next(
        (
            provider
            for provider in response_providers
            if provider["name"] == target_provider
        ),
        None,
    )
    assert (
        response_provider
    ), 'Configured login option "{}" not in /login response: {}'.format()
    new_names = [x["name"] for x in response_provider["urls"]]
    assert len(new_names) == length_no_hides - len(
        expected_hidden_names
    ), "Provider name list is incorrect length"
    # names have been removed
    assert all(name not in new_names for name in expected_hidden_names)
    assert set(new_names) == set(all_names) - set(expected_hidden_names)
