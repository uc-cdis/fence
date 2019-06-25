import pkgutil

import flask
from markdown import Markdown

blueprint = flask.Blueprint("privacy-policy", __name__)


PRIVACY_POLICY_MD = pkgutil.get_data("fence", "static/privacy_policy.md")
PRIVACY_POLICY_HTML = Markdown().convert(PRIVACY_POLICY_MD)


@blueprint.route("/", methods=["GET"])
def privacy_policy():
    if str(flask.request.accept_mimetypes) == "text/markdown":
        return flask.Response(PRIVACY_POLICY_MD, mimetype="text/markdown")
    else:
        return flask.Response(PRIVACY_POLICY_HTML, mimetype="text/html")
