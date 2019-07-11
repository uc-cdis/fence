"""
This blueprint defines the /privacy-policy enpdoint to serve a privacy policy from
fence, which will be linked to in the OAuth2 consent screens.

The logic as to where to get this thing from is as follows.

- If there is a PRIVACY_POLICY_URL environment variable (which should come from the
  manifest, exposed here through the fence deploy file---see manifest and
  `cloud-automation/kube/services/fence/`), then redirect to that URL.
- If the file `fence/static/privacy_policy.md` exists, then return that either as
  markdown or HTML depending on the accept mimetype. This can also be handled via cloud
  automation with a volume mount adding this file, or if you are deploying fence
  standalone and need this feature then you could add the file manually to that path.
"""

import pkgutil
import os

import flask
from markdown import Markdown

from fence import config
from fence.errors import NotFound


blueprint = flask.Blueprint("privacy-policy", __name__)


PRIVACY_POLICY_URL = config.get("PRIVACY_POLICY_URL") or os.environ.get(
    "PRIVACY_POLICY_URL"
)
PRIVACY_POLICY_MD = pkgutil.get_data("fence", "static/privacy_policy.md")
PRIVACY_POLICY_HTML = None
if PRIVACY_POLICY_MD:
    PRIVACY_POLICY_HTML = Markdown().convert(PRIVACY_POLICY_MD)


@blueprint.route("/", methods=["GET"])
def privacy_policy():
    # Check if we want to redirect out for the privacy policy.
    if PRIVACY_POLICY_URL:
        return flask.redirect(PRIVACY_POLICY_URL)
    if "text/markdown" in str(flask.request.accept_mimetypes).lower():
        if not PRIVACY_POLICY_MD:
            raise NotFound("this endpoint is not configured")
        return flask.Response(PRIVACY_POLICY_MD, mimetype="text/markdown")
    else:
        if not PRIVACY_POLICY_HTML:
            raise NotFound("this endpoint is not configured")
        return flask.Response(PRIVACY_POLICY_HTML, mimetype="text/html")
