from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate

import flask
import jwt
import smtplib
import json
from cdislogging import get_logger
from gen3authz.client.arborist.errors import ArboristError

from fence.resources import userdatamodel as udm
from fence.resources.google.utils import (
    get_linked_google_account_email,
    get_linked_google_account_exp,
    get_service_account,
)
from fence.resources.userdatamodel import get_user_groups

from fence.config import config
from fence.errors import NotFound, Unauthorized, UserError, InternalError, Forbidden
from fence.jwt.utils import get_jwt_header
from fence.models import query_for_user


logger = get_logger(__name__)


def update_user_resource(username, resource):
    with flask.current_app.db.session as session:
        user = find_user(username, session)
        if not user.application:
            raise UserError("User haven't started the application")
        resources = set(user.application.resources_granted or [])
        resources.add(resource)
        user.application.resources_granted = list(resources)
        if "EMAIL_SERVER" in config:
            content = "You have been granted {} resources in Bionimbus Cloud.".format(
                ", ".join(resources)
            )
            send_mail(
                config["SEND_FROM"],
                [user.email],
                "Account update from Bionimbus Cloud",
                text=content,
                server=config["EMAIL_SERVER"],
            )
        return get_user_info(user, session)


def update_user(current_session, additional_info):
    usr = get_user(current_session, current_session.merge(flask.g.user).username)

    if usr.additional_info and usr.additional_info != "'{}'":
        raise Forbidden(
                    "You need to be an admin to update user additional information"
                    " if they have been inserted previously"
                )

    udm.update_user(current_session, usr.username, additional_info)
    return get_user_info(current_session, usr.username)


def find_user(username, session):
    user = query_for_user(session=session, username=username)
    if not user:
        raise NotFound("user {} not found".format(username))
    return user


def get_user(current_session, username):
    user = udm.get_user(current_session, username)
    if not user:
        raise NotFound("user {} not found".format(username))
    return user


def get_current_user_info():
    with flask.current_app.db.session as session:
        return get_user_info(session, session.merge(flask.g.user).username)


def get_user_info(current_session, username):
    user = get_user(current_session, username)
    if user.is_admin:
        role = "admin"
    else:
        role = "user"

    groups = udm.get_user_groups(current_session, username)["groups"]
    info = {
        "user_id": user.id,  # TODO deprecated, use 'sub'
        "sub": user.id,
        "username": user.username,  # TODO deprecated, use 'name'
        "name": user.username,
        "additional_info": user.additional_info,
        "display_name": user.display_name,  # TODO deprecated, use 'preferred_username'
        "preferred_username": user.display_name,
        "phone_number": user.phone_number,
        "email": user.email,
        "is_admin": user.is_admin,
        "role": role,
        "project_access": dict(user.project_access),
        "certificates_uploaded": [],
        "resources_granted": [],
        "groups": groups,
        "message": "",
    }

    # User SAs are stored in db with client_id = None
    primary_service_account = get_service_account(client_id=None, user_id=user.id) or {}
    primary_service_account_email = getattr(primary_service_account, "email", None)
    info["primary_google_service_account"] = primary_service_account_email

    if hasattr(flask.current_app, "arborist"):
        try:
            resources = flask.current_app.arborist.list_resources_for_user(
                user.username
            )
            auth_mapping = flask.current_app.arborist.auth_mapping(user.username)
        except ArboristError:
            logger.error(
                "request to arborist for user's resources failed; going to list empty"
            )
            resources = []
            auth_mapping = {}
        info["resources"] = resources
        info["authz"] = auth_mapping

    if user.tags is not None and len(user.tags) > 0:
        info["tags"] = {tag.key: tag.value for tag in user.tags}

    if user.application:
        info["resources_granted"] = user.application.resources_granted
        info["certificates_uploaded"] = [
            c.name for c in user.application.certificates_uploaded
        ]
        info["message"] = user.application.message

    if flask.request.get_json(force=True, silent=True):
        requested_userinfo_claims = (
            flask.request.get_json(force=True).get("claims", {}).get("userinfo", {})
        )
        optional_info = _get_optional_userinfo(user, requested_userinfo_claims)
        info.update(optional_info)

    # Include ga4gh passport visas if access token has ga4gh_passport_v1 in scope claim
    try:
        encoded_access_token = flask.g.access_token or get_jwt_header()
    except Unauthorized:
        # This only happens if a session token was present (since login_required did not throw an error)
        # but for some reason there was no access token in flask.g.access_token.
        # (Perhaps it was manually deleted by the user.)
        # In particular, a curl request made with no tokens shouldn't get here (bc of login_required).
        # So the request is probably from a browser.
        logger.warning(
            "Session token present but no access token found. "
            "Unable to check scopes in userinfo; some claims may not be included in response."
        )
        encoded_access_token = None

    if encoded_access_token:
        at_scopes = jwt.decode(encoded_access_token, verify=False).get("scope", "")
        if "ga4gh_passport_v1" in at_scopes:
            encoded_visas = [row.ga4gh_visa for row in user.ga4gh_visas_v1]
            info["ga4gh_passport_v1"] = encoded_visas

    return info


def _get_optional_userinfo(user, claims):
    info = {}
    for claim in claims:
        if claim == "linked_google_account":
            google_email = get_linked_google_account_email(user.id)
            info["linked_google_account"] = google_email
        if claim == "linked_google_account_exp":
            google_account_exp = get_linked_google_account_exp(user.id)
            info["linked_google_account_exp"] = google_account_exp

    return info


def send_mail(send_from, send_to, subject, text, server, certificates=None):
    assert isinstance(send_to, list)
    msg = MIMEMultipart(
        From=send_from, To=COMMASPACE.join(send_to), Date=formatdate(localtime=True)
    )
    msg["Subject"] = subject
    msg.attach(MIMEText(text))

    for cert in certificates or []:
        application = MIMEApplication(cert.data, cert.extension)
        application.add_header(
            "Content-Disposition", 'attachment; filename="{}"'.format(cert.filename)
        )
        application.set_param("name", cert.filename)
        msg.attach(application)
    smtp = smtplib.SMTP(server)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()


def get_user_accesses():
    user = udm.get_user_accesses()
    if not user:
        raise InternalError("Error: %s user does not exist" % flask.g.user.username)
    return user


def remove_user_from_project(current_session, user, project):
    access = udm.get_user_project_access_privilege(current_session, user, project)
    if access:
        current_session.delete(access)
    else:
        raise NotFound(
            "Project {0} not connected to user {1}".format(project.name, user.username)
        )
