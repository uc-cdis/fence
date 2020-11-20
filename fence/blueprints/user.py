import flask
from flask_sqlalchemy_session import current_session

from fence.auth import login_required, current_token
from fence.errors import Unauthorized, UserError, NotFound
from fence.models import Application, Certificate
from fence.resources.user import send_mail, get_current_user_info, update_user
from fence.config import config


REQUIRED_CERTIFICATES = {
    "AUP_COC_NDA": "documents needed for user e-sign",
    "training_certificate": "certificate obtained from training",
}

blueprint = flask.Blueprint("user", __name__)


@blueprint.route("/", methods=["GET", "POST"])
@login_required({"user"})
def user_info():
    client_id = None
    if current_token and current_token["azp"]:
        client_id = current_token["azp"]
    info = get_current_user_info()
    info["azp"] = client_id
    return flask.jsonify(info)


@blueprint.route("/", methods=["PUT"])
@login_required({"user"})
def update_user_info():
    firstName = flask.request.get_json().get("firstName", None)
    lastName = flask.request.get_json().get("lastName", None)
    institution = flask.request.get_json().get("institution", None)
    additional_info = {}

    if firstName:
        additional_info["firstName"] = firstName
    if lastName:
        additional_info["lastName"] = lastName
    if institution:
        additional_info["institution"] = institution
        
    return flask.jsonify(update_user(current_session, additional_info))


@blueprint.route("/anyaccess", methods=["GET"])
@login_required({"user"})
def any_access():
    """
    Check if the user is in our database

    :note if a user is specified with empty access it still counts

    :query project: (optional) Check for read access to a specific program/project

    """
    project = flask.request.args.get("project")
    projects = None
    if flask.g.token is None:
        flask.g.user = current_session.merge(flask.g.user)
        projects = flask.g.user.project_access
    else:
        projects = flask.g.token["context"]["user"]["projects"]

    success = False

    if not project and len(projects) > 0:
        success = True
    elif project and project in projects:
        access = projects[project]
        if "read" in access:
            success = True

    if success:
        resp = flask.make_response(flask.jsonify({"result": "success"}), 200)
        resp.headers["REMOTE_USER"] = flask.g.user.username
        return resp
    raise Unauthorized("Please login")


@blueprint.route("/cert", methods=["GET"])
@login_required({"user"})
def missing_certificate():
    flask.g.user = current_session.merge(flask.g.user)
    if not flask.g.user.application:
        return flask.jsonify(REQUIRED_CERTIFICATES)
    certificates = [c.name for c in flask.g.user.application.certificates_uploaded]
    missing = set(REQUIRED_CERTIFICATES.keys()).difference(certificates)
    return flask.jsonify({k: REQUIRED_CERTIFICATES[k] for k in missing})


@blueprint.route("/cert/<certificate>", methods=["PUT"])
@login_required({"user"})
def upload_certificate(certificate):
    extension = flask.request.args.get("extension")
    allowed_extension = ["pdf", "png", "jpg", "jpeg", "txt"]
    if not extension or extension not in allowed_extension:
        raise UserError(
            "Invalid extension in parameter, acceptable extensions are {}".format(
                ", ".join(allowed_extension)
            )
        )

    if not flask.g.user.application:
        flask.g.user.application = Application()
        current_session.merge(flask.g.user)
    cert = (
        current_session.query(Certificate)
        .filter(Certificate.name == certificate)
        .filter(Certificate.application_id == flask.g.user.application.id)
        .first()
    )
    if not cert:
        cert = Certificate(name=certificate)
    cert.application_id = flask.g.user.application.id
    cert.extension = extension
    cert.data = flask.request.data
    current_session.merge(cert)

    certificates = flask.g.user.application.certificates_uploaded
    if set(REQUIRED_CERTIFICATES.keys()).issubset(set(c.name for c in certificates)):
        title = "User application for {}".format(flask.g.user.username)
        if getattr(flask.g, "client"):
            title += " from {}".format(flask.g.client)
        if "EMAIL_SERVER" in config:
            content = "Application for user: {}\n" "email: {}".format(
                flask.g.user.username, flask.g.user.email
            )
            send_mail(
                config["SEND_FROM"],
                config["SEND_TO"],
                title,
                text=content,
                server=config["EMAIL_SERVER"],
                certificates=certificates,
            )
    return "", 201


@blueprint.route("/cert/<certificate>", methods=["GET"])
@login_required({"user"})
def download_certificate(certificate):
    if not flask.g.user.application:
        flask.g.user.application = Application()
        current_session.merge(flask.g.user)
    cert = (
        current_session.query(Certificate)
        .filter(Certificate.name == certificate)
        .filter(Certificate.application_id == flask.g.user.application.id)
        .first()
    )
    if cert:
        resp = flask.make_response(cert.data)
        resp.headers["Content-Type"] = "application/octet-stream"
        resp.headers["Content-Disposition"] = "attachment; filename={}.{}".format(
            cert.name, cert.extension
        )
        return resp
    else:
        raise NotFound("No certificate with name {} found".format(certificate))
