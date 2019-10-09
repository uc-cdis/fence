from urllib.parse import urlencode

from fence.config import config


def test_default_login(app, client):
    response_json = client.get("/login").json
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


def test_enabled_logins(app, client):
    response_json = client.get("/login").json
    assert "providers" in response_json
    response_providers = response_json["providers"]
    configured_logins = config["LOGIN_OPTIONS"]

    # Check all providers in the response have the expected idp, name, URLs,
    # desc and secondary information
    app_urls = [url_map_rule.rule for url_map_rule in app.url_map._rules]
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
        if "shib_idps" in configured:
            for shib_idp in configured["shib_idps"]:
                assert any(
                    urlencode({"shib_idp": shib_idp}) in url_info["url"]
                    for url_info in response_provider["urls"]
                ), 'shib_idp param "{}", encoded "{}", is not in provider\'s login URLs: {}'.format(
                    shib_idp,
                    urlencode({"shib_idp": shib_idp}),
                    response_provider["urls"],
                )
        login_urls = [
            url_info["url"].replace(config["BASE_URL"], "").split("?")[0]
            for url_info in response_provider["urls"]
        ]
        assert all(url in app_urls for url in login_urls)
