from flask import current_app as capp

from flask import jsonify, g

from fence.errors import NotFound, UserError, InternalError
from fence.data_model.models import User

import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate
from flask_sqlalchemy_session import current_session
from fence.resources import userdatamodel as udm

def update_user_resource(username, resource):
    with capp.db.session as session:
        user = find_user(username, session)
        if not user.application:
            raise UserError("User haven't started the application")
        resources = set(user.application.resources_granted or [])
        resources.add(resource)
        user.application.resources_granted = list(resources)
        if 'EMAIL_SERVER' in capp.config:
            content = (
                "You have been granted {} resources in Bionimbus Cloud."
                .format(', '.join(resources)))
            send_mail(
                capp.config['SEND_FROM'],
                [user.email],
                'Account update from Bionimbus Cloud',
                text=content,
                server=capp.config['EMAIL_SERVER'])
        return get_user_info(user, session)


def get_user(current_session, username):
    user = current_session.query(User).filter(User.username == username).first()
    if not user:
        raise NotFound("user {} not found".format(username))
    return user


def get_current_user_info():
    with capp.db.session as session:
        return get_user_info(session.merge(g.user), session)


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
        'resources_granted': [],
        'project_access': dict(user.project_access),
        'certificates_uploaded': [],
        'email': user.email,
        'message': '',
        'role': role,
        'groups': groups
    }
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
    user = current_session.query(User)\
        .join(User.research_groups)\
        .filter(User.id == g.user.id)
    if not user:
        raise InternalError("Error: %s user does not exist in user-data-model" % g.user.username)
    return user

def get_user_groups(current_session, username):
    return udm.get_user_groups(current_session, username)

def remove_user_from_project(curren_session, user, project):
    return udm.remove_user_from_project(current_session, user, project)
