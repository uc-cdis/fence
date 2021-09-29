from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback


def test_map_user_idp_info():
    oauth2callback = DefaultOAuth2Callback("mock_idp")
