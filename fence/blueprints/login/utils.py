from urllib.parse import urlparse

import flask

from fence.config import config
from fence.models import Client


def allowed_login_redirects():
    """
    Determine which redirects a login redirect endpoint (``/login/google``, etc) should
    be allowed to redirect back to after login. By default this includes the base URL
    from this flask application, and also includes the redirect URLs registered for any
    OAuth clients.

    Return:
        List[str]: allowed redirect URLs
    """
    allowed = config.get("LOGIN_REDIRECT_WHITELIST", [])
    allowed.append(config["BASE_URL"])
    with flask.current_app.db.session as session:
        clients = session.query(Client).all()
        for client in clients:
            allowed.extend(client.redirect_uris)
    return {domain(url) for url in allowed}


def domain(url):
    """
    Return just the domain for a URL, no schema or path etc. This is to consistently
    compare different URLs from flask, the config, and from the user.
    """
    if not url:
        return ""
    if url.startswith("/"):
        return urlparse(config["BASE_URL"]).netloc
    return urlparse(url).netloc
