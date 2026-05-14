import flask
from flask import current_app

from fence.auth import login_required
from fence.errors import UserError
from fence.config import config

from fence.blueprints.data.indexd import (
    get_signed_url_for_file,
)
from fence.models import UserPassport
from fence.resources.user import get_current_user_info

blueprint = flask.Blueprint("ga4gh", __name__)


@blueprint.route(
    "/drs/v1/objects/<path:object_id>/access/",
    defaults={"access_id": None},
    methods=["GET"],
)
@blueprint.route(
    "/drs/v1/objects/<path:object_id>/access/<path:access_id>",
    methods=["GET", "POST"],
)
def get_ga4gh_signed_url(object_id, access_id):
    if not access_id:
        raise UserError("Access ID/Protocol is required.")

    ga4gh_passports = None
    if flask.request.method == "POST":
        ga4gh_passports = flask.request.get_json(force=True, silent=True).get(
            config["GA4GH_DRS_POSTED_PASSPORT_FIELD"]
        )

        if ga4gh_passports and flask.request.headers.get("Authorization"):
            raise UserError(
                "You cannot supply both GA4GH passports and a token "
                "in the Authorization header of a request."
            )

    result = get_signed_url_for_file(
        "download",
        object_id,
        requested_protocol=access_id,
        ga4gh_passports=ga4gh_passports,
        drs="True",
    )

    return flask.jsonify(result)


@blueprint.route(
    "/__passport",
    methods=["GET", "POST"],
)
@login_required({"user"})
def get_passport():
    info = get_current_user_info()
    user_id = info["user_id"]
    db_session = current_app.scoped_session()
    passport = db_session.query(UserPassport).filter_by(user_id=int(user_id)).first()
    return flask.jsonify({"passport": passport.passport})
