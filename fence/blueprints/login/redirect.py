"""
Define the redirect URL validation for the login resources (which also live in this same
folder).
"""

import re

from cdislogging import get_logger
import flask

from fence.utils import allowed_login_redirects, domain
from fence.errors import UserError


logger = get_logger(__name__)

# ASCII control characters: C0 (0x00-0x1F) and DEL (0x7F).
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def validate_redirect(url):
    """
    Complain if a given URL is not on the login redirect whitelist.

    For example, links like the following should be disallowed:

        https://gen3.datacommons.io/user/login/fence?redirect=http://external-site.com

    Only callable from inside flask application context.

    Args:
        url (str)
        oauth_client (fence.models.Client)

    Return:
        None

    Raises:
        UserError: if redirect URL in the request is disallowed
    """
    # Werkzeug's Location handling (via urlsplit) deletes tab, CR and LF anywhere in
    # the URL, so "/\t/external-site.com" would be checked here as a local path but
    # sent to the browser as "//external-site.com". Reject rather than strip, so the
    # URL that passes this check is exactly the one stored for the redirect.
    if url and _CONTROL_CHARS.search(url):
        logger.error("invalid redirect {!r}: contains control characters".format(url))
        raise UserError("invalid login redirect URL")

    allowed_redirects = allowed_login_redirects()
    if domain(url) not in allowed_redirects:
        logger.error(
            "invalid redirect {}. expected one of: {}".format(url, allowed_redirects)
        )
        raise UserError("invalid login redirect URL {}".format(url))
