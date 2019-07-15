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
from werkzeug.contrib.cache import SimpleCache

from fence import config
from fence.errors import NotFound


blueprint = flask.Blueprint("privacy-policy", __name__)

cache = SimpleCache()


@blueprint.route("/", methods=["GET"])
def privacy_policy():
    # Check if we want to redirect out for the privacy policy.
    privacy_policy_url = config.get("PRIVACY_POLICY_URL") or os.environ.get(
        "PRIVACY_POLICY_URL"
    )
    if privacy_policy_url:
        return flask.redirect(privacy_policy_url)

    global cache
    if not cache.has("privacy-policy-md"):
        file_contents = pkgutil.get_data("fence", "static/privacy_policy.md").decode(
            "utf-8"
        )
        if not file_contents:
            raise NotFound("this endpoint is not configured")
        cache.add("privacy-policy-md", file_contents)

    if "text/markdown" in str(flask.request.accept_mimetypes).lower():
        return flask.Response(cache.get("privacy-policy-md"), mimetype="text/markdown")
    else:
        if not cache.has("privacy-policy-html"):
            html = Markdown().convert(cache.get("privacy-policy-md"))
            if not html:
                raise NotFound("this endpoint is not configured")
            cache.add("privacy-policy-html", html)
        return flask.Response(cache.get("privacy-policy-html"), mimetype="text/html")
