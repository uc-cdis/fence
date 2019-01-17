from urlparse import urlparse

import flask

from fence.config import config
from fence.models import Client


def allowed_login_redirects():
    """
    Determine which redirects a login redirect endpoint (``/login/google``, etc)
    should be allowed to redirect back to after login. By default this includes the
    base URL from this flask application, and also includes the redirect URLs
    registered for any OAuth clients.

    Return:
        List[str]: allowed redirect URLs
    """
    allowed = config.get("LOGIN_REDIRECT_WHITELIST", [])
    allowed.append(config["BASE_URL"])
    if "fence" in config.get("OPENID_CONNECT", {}):
        allowed.append(
            config["BASE_URL"].rstrip("/") + flask.url_for("login.fencelogin")
        )
    with flask.current_app.db.session as session:
        clients = session.query(Client).all()
        for client in clients:
            allowed.extend(client.redirect_uris)
    return {domain(url) for url in allowed}


def domain(url):
    """Return just the domain for a URL, no schema or path etc."""
    return urlparse(url).netloc
