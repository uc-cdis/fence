from fence.jwt.blacklist import blacklist_token, is_blacklisted, is_token_blacklisted

from tests import utils


def test_jti_not_blacklisted(app):
    """
    Test checking a ``jti`` which has not been blacklisted.
    """
    assert not is_blacklisted(utils.new_jti())


def test_blacklist(app):
    """
    Test blacklisting a ``jti`` directly.
    """
    _, exp = utils.iat_and_exp()
    jti = utils.new_jti()
    blacklist_token(jti, exp)
    assert is_blacklisted(jti)


def test_normal_token_not_blacklisted(app, encoded_jwt_refresh_token):
    """
    Test that a (refresh) token which was not blacklisted returns not
    blacklisted.
    """
    assert not is_token_blacklisted(encoded_jwt_refresh_token)
