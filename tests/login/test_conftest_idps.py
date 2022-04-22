import os

from tests.conftest import LOGIN_IDPS


def test_contfest_idps():
    """
    This test checks that any newly added custom OIDC IDP has been added to
    the list of IDPs to test (LOGIN_IDPS).

    If you added an IDP and this test fails, do not edit this test. Either the
    new IDP should be added to LOGIN_IDPS and test-fence-config.yaml's
    OPENID_CONNECT, or the new file names do not match the convention and
    cannot be parsed by this test.
    """
    current_dir = os.path.dirname(os.path.realpath(__file__))
    err_msg = "For IDP file '{}': IDP '{}' should be added to the tests' 'LOGIN_IDPS' to be tested"

    subdir = "resources/openid"
    path = os.path.join(current_dir, "../../fence", subdir)
    for _, _, files in os.walk(path):
        for f in files:
            if f.startswith("__") or f == "idp_oauth2.py":
                continue
            idp = f.split("_")[0]
            assert idp in LOGIN_IDPS, err_msg.format(os.path.join(subdir, f), idp)
        break  # no need to check subdirectories

    subdir = "blueprints/login"
    path = os.path.join(current_dir, "../../fence", subdir)
    for _, _, files in os.walk(path):
        for f in files:
            if f.startswith("__") or f in ["base.py", "redirect.py", "utils.py"]:
                continue
            idp = f.split(".py")[0].split("_login")[0]
            assert idp in LOGIN_IDPS, err_msg.format(os.path.join(subdir, f), idp)
        break  # no need to check subdirectories
