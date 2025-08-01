import os

from fence.config import config
from tests.conftest import all_available_idps


def test_contfest_idps():
    """
    This test checks that any newly added custom OIDC IdP is in
    the list of IdPs to test (all_enabled_login_idps).

    If you added an IdP and this test fails, DO NOT edit this test. Either the
    new IdP should be added to test-fence-config.yaml's OPENID_CONNECT+LOGIN_OPTIONS,
    or the new file names do not match the convention and cannot be parsed by this test.
    """
    all_enabled_login_idps = list(set(config["OPENID_CONNECT"].keys()))
    current_dir = os.path.dirname(os.path.realpath(__file__))
    err_msg = "For IdP file '{}': IdP '{}' must be added to test-fence-config.yaml's OPENID_CONNECT+LOGIN_OPTIONS to be tested"

    subdir = "resources/openid"
    path = os.path.join(current_dir, "../../fence", subdir)
    for _, _, files in os.walk(path):
        for f in files:
            if f.startswith("__") or f == "idp_oauth2.py":
                continue
            idp = f.split("_")[0]
            if idp == "shib":
                idp = "shibboleth"  # see `get_idp_route_name` function
            assert idp in all_enabled_login_idps, err_msg.format(
                os.path.join(subdir, f), idp
            )
        break  # no need to check subdirectories

    # `all_available_idps` == `blueprints/login` subdir
    for idp in all_available_idps():
        assert idp in all_enabled_login_idps, err_msg.format(
            os.path.join(subdir, f), idp
        )
