"""
WISEcode Platform login resource
"""

import flask
from flask_restful import Resource
import time
import logging

from fence.user import get_current_user
from fence.config import config
from fence.blueprints.login.base import _login, prepare_login_log
from fence.errors import UserError
from fence.models import IdentityProvider
from fence.jwt.token import generate_signed_access_token
from fence.utils import cognito_user_jwt


log = logging.getLogger(__name__)


class WISEcodePlatformLogin(Resource):
    """
    WISEcode Platform login resource
    """

    def post(self):
        """
        Processes requests from the WISEcode for Business Platform. The platform calls this endpoint with its user's Cognito
        JWT in the Authorization header. This handler calls the WISEcode User service Read JWT User service action
        to validate the JWT and get the user resource. Last, a Fence JWT is made and added to a cookie in the reponse.
        """

        try:
            log.info("handling WISEcode login request")
            username, password = flask.request.json.get("username"), flask.request.json.get("password")
            if username and password:
                cognito_jwt = cognito_user_jwt(username, password)
                if cognito_jwt:
                    _login(username, IdentityProvider.wisecode, email=username)
                    prepare_login_log(IdentityProvider.wisecode)
                    keypair = flask.current_app.keypairs[0]
                    scopes = config["SESSION_ALLOWED_SCOPES"]
                    now = int(time.time())
                    expiration = now + config.get("ACCESS_TOKEN_EXPIRES_IN")
                    fence_jwt = generate_signed_access_token(
                        keypair.kid,
                        keypair.private_key,
                        get_current_user(),
                        config.get("ACCESS_TOKEN_EXPIRES_IN"),
                        scopes,
                        forced_exp_time=expiration,
                    ).token
                    response = flask.jsonify(
                        {
                            "fenceJwt": fence_jwt,
                            "cognitoJwt": cognito_jwt
                        }
                    )
                    response.headers.add("Access-Control-Allow-Origin", "*")
                    return response
        except Exception as e:
            log.error(f"Failed processing WISEcode login with {e}")

        raise UserError("WISEcode user not found")
