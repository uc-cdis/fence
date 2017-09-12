import json

from cdispyutils.constants import ALGORITHM as hmac_algorithm
from cdispyutils.hmac4 import verify_hmac
from cdispyutils.hmac4.hmac4_auth_utils import HMAC4Error
from cryptography.fernet import Fernet
from flask import current_app as capp
from flask import g, jsonify
from flask_jwt_extended import create_access_token
from flask_sqlalchemy_session import current_session
from userdatamodel.models import HMACKeyPair

from .errors import Unauthorized


def get_secret_key(access_key):
    """
    Get secret key from database, also set g.user to the user who owns
    the keypair as a side effect
    """
    hmac_keypair = (
        current_session.query(HMACKeyPair)
        .filter(HMACKeyPair.access_key == access_key)
        .first()
    )
    if not hmac_keypair:
        raise Unauthorized("Access key doesn't exist.")

    g.user = hmac_keypair.user
    key = Fernet(bytes(capp.config['HMAC_ENCRYPTION_KEY']))
    return key.decrypt(bytes(hmac_keypair.secret_key))


def hmac_to_jwt(request, service):
    """
    Check hmac Authorization header, if it's valid, return
    a json response of access_token
    """
    if 'Authorization' not in request.headers:
        raise Unauthorized("No authentication provided")

    header = request.headers['Authorization']
    parts = header.split(' ')
    if len(parts) > 1:
        algorithm = header.split(' ')[0]
        if algorithm == hmac_algorithm:
            try:
                verify_hmac(
                    request, service, get_secret_key
                )
            except HMAC4Error as e:
                capp.logger.exception("fail")
                print e.json
                raise Unauthorized(e.message + str(e.json))
        else:
            raise Unauthorized("Unsupported authorization type")
    else:
        raise Unauthorized("Unsupported authorization type")

    identity = json.dumps({
        'username': g.user.username,
        'project_access': dict(g.user.project_access),
    })
    ret = {'access_token': create_access_token(identity=identity)}
    return jsonify(ret), 200
