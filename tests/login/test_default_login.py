from fence.config import config


def test_default_login(app, client):
    response_json = client.get("/login").json
    assert "default_provider" in response_json
    assert "providers" in response_json
    response_default = response_json["default_provider"]
    response_providers = response_json["providers"]
    idps = config["ENABLED_IDENTITY_PROVIDERS"]["providers"]
    default_idp_id = config["ENABLED_IDENTITY_PROVIDERS"]["default"]
    # Check default IDP is correct.
    assert response_default["id"] == default_idp_id
    assert response_default["name"] == idps[default_idp_id]["name"]
    # Check all providers in response: expected ID, expected name, URL actually
    # maps correctly to the endpoint on fence.
    app_urls = [url_map_rule.rule for url_map_rule in app.url_map._rules]
    for response_idp in response_providers:
        assert response_idp["id"] in idps
        assert response_idp["name"] == idps[response_idp["id"]]["name"]
        login_url = response_idp["url"].replace(config["BASE_URL"], "")
        assert login_url in app_urls
