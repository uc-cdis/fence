import pkgutil

import flask
from markdown import Markdown

from fence import config

blueprint = flask.Blueprint("privacy-policy", __name__)


PRIVACY_POLICY_MD = pkgutil.get_data("fence", "static/privacy_policy.md")
PRIVACY_POLICY_HTML = Markdown().convert(PRIVACY_POLICY_MD)


@blueprint.route("/", methods=["GET"])
def privacy_policy():
    # Check if we want to redirect out for the privacy policy.
    if config.get("PRIVACY_POLICY"):
        return flask.redirect(config["PRIVACY_POLICY"])
    if "text/markdown" in str(flask.request.accept_mimetypes).lower():
        return flask.Response(PRIVACY_POLICY_MD, mimetype="text/markdown")
    else:
        return flask.Response(PRIVACY_POLICY_HTML, mimetype="text/html")
