from fence.config import config


def test_default_login(app, client):
    response_json = client.get("/login").json
    assert "default_provider" in response_json
    assert "providers" in response_json
    response_default = response_json["default_provider"]
    response_providers = response_json["providers"]
    configured_logins = config["ENABLED_IDENTITY_PROVIDERS"]["login_options"]
    default_idp = config["ENABLED_IDENTITY_PROVIDERS"]["default"]

    # Check default IDP is correct.
    assert response_default["idp"] == default_idp
    names_for_this_idp = [
        login_details["name"]
        for login_details in configured_logins
        if login_details["idp"] == default_idp
    ]
    assert response_default["name"] in names_for_this_idp

    # Check all providers in response: expected ID, expected name, URL actually
    # maps correctly to the endpoint on fence.
    app_urls = [url_map_rule.rule for url_map_rule in app.url_map._rules]
    for configured in configured_logins:
        # assumes unique idp/name couples in test config
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
        ), "Configured login option {} not in /login response {}".format()
        if "desc" in configured:
            assert response_provider["desc"] == configured["desc"]
        if "secondary" in configured:
            assert response_provider["secondary"] == configured["secondary"]
        if "shib_idps" in configured:
            assert response_provider["shib_idps"] == configured["shib_idps"]
        login_url = response_provider["url"].replace(config["BASE_URL"], "")
        assert login_url in app_urls
