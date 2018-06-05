from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
import flask
from fence.resources import userdatamodel as udm
from fence.resources.userdatamodel import delete_user, get_user_groups
import smtplib
from sqlalchemy import func

from fence.errors import NotFound, UserError, InternalError
from fence.models import User


def update_user_resource(username, resource):
    with flask.current_app.db.session as session:
        user = find_user(username, session)
        if not user.application:
            raise UserError("User haven't started the application")
        resources = set(user.application.resources_granted or [])
        resources.add(resource)
        user.application.resources_granted = list(resources)
        if 'EMAIL_SERVER' in flask.current_app.config:
            content = (
                "You have been granted {} resources in Bionimbus Cloud."
                .format(', '.join(resources)))
            send_mail(
                flask.current_app.config['SEND_FROM'],
                [user.email],
                'Account update from Bionimbus Cloud',
                text=content,
                server=flask.current_app.config['EMAIL_SERVER'])
        return get_user_info(user, session)


def find_user(username, session):
    user = session.query(User).filter(func.lower(User.username) == username.lower()).first()
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
        return flask.jsonify(get_user_info(session, session.merge(flask.g.user).username))


def get_user_info(current_session, username):
    user = get_user(current_session, username)
    if user.is_admin:
        role = 'admin'
    else:
        role = 'user'
    groups = udm.get_user_groups(current_session, username)['groups']
    info = {
        'user_id': user.id,
        'username': user.username,
        'display_name': user.display_name,
        'phone_number': user.phone_number,
        'resources_granted': [],
        'project_access': dict(user.project_access),
        'certificates_uploaded': [],
        'email': user.email,
        'message': '',
        'role': role,
        'groups': groups
    }
    if user.tags is not None and len(user.tags) > 0:
        info['tags'] = {tag.key: tag.value for tag in user.tags}

    if user.application:
        info['resources_granted'] = user.application.resources_granted
        info['certificates_uploaded'] = [
            c.name for c in user.application.certificates_uploaded]
        info['message'] = user.application.message
    return info


def send_mail(send_from, send_to, subject, text, server, certificates=None):
    assert isinstance(send_to, list)
    msg = MIMEMultipart(
        From=send_from,
        To=COMMASPACE.join(send_to),
        Date=formatdate(localtime=True),
    )
    msg['Subject'] = subject
    msg.attach(MIMEText(text))

    for cert in certificates or []:
        application = MIMEApplication(cert.data, cert.extension)
        application.add_header(
            'Content-Disposition', 'attachment; filename="{}"'
            .format(cert.filename))
        application.set_param('name', cert.filename)
        msg.attach(application)
    smtp = smtplib.SMTP(server)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()


def get_user_accesses():
    user = udm.get_user_accesses()
    if not user:
        raise InternalError(
            'Error: %s user does not exist'
            % flask.g.user.username
        )
    return user


def remove_user_from_project(current_session, user, project):
    access = udm.get_user_project_access_privilege(current_session, user, project)
    if access:
        current_session.delete(access)
    else:
        raise NotFound("Project {0} not connected to user {1}".format(
            project.name, user.username))
