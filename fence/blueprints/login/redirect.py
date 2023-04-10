"""
Define the redirect URL validation for the login resources (which also live in this same
folder).
"""

from cdislogging import get_logger

from fence.blueprints.login.utils import allowed_login_redirects, domain
from fence.errors import UserError


logger = get_logger(__name__)


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
    allowed_redirects = allowed_login_redirects()
    if domain(url) not in allowed_redirects:
        logger.error(
            "invalid redirect {}. expected one of: {}".format(url, allowed_redirects)
        )
        raise UserError("invalid login redirect URL {}".format(url))
