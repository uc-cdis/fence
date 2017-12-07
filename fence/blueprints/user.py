import flask
from fence.auth import login_required
from flask import jsonify, g, make_response
from flask_oauthlib.provider import OAuth2Provider
from fence.errors import UserError, NotFound
from userdatamodel.models import *  # noqa
from fence.resources.user import send_mail, get_current_user_info
from flask import current_app as capp
from flask import request
from flask_sqlalchemy_session import current_session

oauth = OAuth2Provider()


def init_oauth(app):
    oauth.init_app(app)


REQUIRED_CERTIFICATES = {
    'AUP_COC_NDA': 'documents needed for user e-sign',
    'training_certificate': 'certificate obtained from training'
}

blueprint = flask.Blueprint('user', __name__)


@blueprint.route('/', methods=['GET'])
@login_required({'user'})
def user_info():
    return get_current_user_info()


@blueprint.route('/cert', methods=['GET'])
@login_required({'user'})
def missing_certificate():
    g.user = current_session.merge(g.user)
    if not g.user.application:
        return jsonify(REQUIRED_CERTIFICATES)
    certificates = [
        c.name for c in g.user.application.certificates_uploaded]
    missing = set(REQUIRED_CERTIFICATES.keys()).difference(certificates)
    return jsonify({k: REQUIRED_CERTIFICATES[k] for k in missing})


@blueprint.route('/cert/<certificate>', methods=['PUT'])
@login_required({'user'})
def upload_certificate(certificate):
    extension = request.args.get('extension')
    allowed_extension = ['pdf', 'png', 'jpg', 'jpeg', 'txt']
    if not extension or extension not in allowed_extension:
        raise UserError(
            "Invalid extension in parameter, acceptable extensions are {}"
            .format(", ".join(allowed_extension)))

    if not g.user.application:
        g.user.application = Application()
        current_session.merge(g.user)
    cert = (
        current_session.query(Certificate)
        .filter(Certificate.name == certificate)
        .filter(Certificate.application_id == g.user.application.id)
        .first()
    )
    if not cert:
        cert = Certificate(name=certificate)
    cert.application_id = g.user.application.id
    cert.extension = extension
    cert.data = request.data
    current_session.merge(cert)

    certificates = g.user.application.certificates_uploaded
    if set(REQUIRED_CERTIFICATES.keys()).issubset(
            set(c.name for c in certificates)):
        title = 'User application for {}'.format(g.user.username)
        if getattr(g, 'client'):
            title += ' from {}'.format(g.client)
        if 'EMAIL_SERVER' in capp.config:
            content = (
                "Application for user: {}\n"
                "email: {}"
                .format(g.user.username, g.user.email)
            )
            send_mail(
                capp.config['SEND_FROM'],
                capp.config['SEND_TO'],
                title,
                text=content,
                server=capp.config['EMAIL_SERVER'],
                certificates=certificates)
    return "", 201


@blueprint.route('/cert/<certificate>', methods=['GET'])
@login_required({'user'})
def download_certificate(certificate):
    if not g.user.application:
        g.user.application = Application()
        current_session.merge(g.user)
    cert = (
        current_session.query(Certificate)
        .filter(Certificate.name == certificate)
        .filter(Certificate.application_id == g.user.application.id)
        .first())
    if cert:
        resp = make_response(cert.data)
        resp.headers['Content-Type'] = 'application/octet-stream'
        resp.headers['Content-Disposition'] =\
            'attachment; filename={}.{}'.format(cert.name, cert.extension)
        return resp
    else:
        raise NotFound(
            'No certificate with name {} found'.format(certificate))
