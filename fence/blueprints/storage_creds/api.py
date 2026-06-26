import json

import flask
from flask_restful import Resource
import jwt

from fence.auth import require_auth_header, current_token, get_user_from_claims
from fence.authz.auth import can_user_get_task_token
from fence.errors import Forbidden, UserError
from fence.jwt.blacklist import blacklist_token
from fence.models import UserRefreshToken
from fence.config import config

from fence.resources.storage.cdis_jwt import create_user_access_token, create_api_key


class ApiKeyList(Resource):
    """
    For ``/credentials/api`` endpoint.
    """

    @require_auth_header({"credentials"})
    def get(self):
        """
        List access keys for user

        **Example:**
        .. code-block:: http

               POST /credentials/apis/ HTTP/1.1
               Content-Type: application/json
               Accept: application/json

        .. code-block:: JavaScript

            {
                "jtis":
                [
                   {"jti": "e9d58890-99b0-44f0-88bd-3ebc370b1329", "exp": 12345678},
                   {"jti": "e9d58890-99b0-44f0-88bd-3ebc370b132a", "exp": 17245678}
                ]
            }
        """
        user_id = current_token["sub"]

        with flask.current_app.db.session as session:
            tokens = (
                session.query(UserRefreshToken)
                .filter_by(userid=user_id)
                .order_by(UserRefreshToken.expires.desc())
                .all()
            )
            result = {
                "jtis": [{"jti": item.jti, "exp": item.expires} for item in tokens]
            }

        return flask.jsonify(result)

    @require_auth_header({"credentials"})
    def post(self):
        """
        Generate a key for user

        **Example:**
        .. code-block:: http

               POST /credentials/api/?expires_in=3600 HTTP/1.1
               Content-Type: application/json
               Accept: application/json

        .. code-block:: JavaScript

            {
                "key_id": result,
                "api_key": result
            }
        """
        client_id = current_token.get("azp") or None
        user_id = current_token["sub"]

        # fence identifies access_token endpoint, openid is the default
        # scope for service endpoints
        default_scope = ["fence", "openid"]
        content_type = flask.request.headers.get("Content-Type")
        if content_type == "application/x-www-form-urlencoded":
            scope = flask.request.form.getlist("scope")
        else:
            try:
                scope = (json.loads(flask.request.data).get("scope")) or []
            except ValueError:
                scope = []
        if not isinstance(scope, list):
            scope = scope.split(",")
        scope.extend(default_scope)
        for s in scope:
            if s not in config["USER_ALLOWED_SCOPES"]:
                flask.abort(400, "Scope {} is not supported".format(s))

        # add all scopes from the user's access token;
        # remove any scopes that have been removed from USER_ALLOWED_SCOPES
        scope.extend(
            [s for s in current_token["scope"] if s in config["USER_ALLOWED_SCOPES"]]
        )

        # a token created using an API key cannot be used to create a new API key
        scope = [s for s in set(scope) if s != "credentials"]

        max_ttl = config.get("MAX_API_KEY_TTL", 2592000)
        expires_in = min(int(flask.request.args.get("expires_in", max_ttl)), max_ttl)
        api_key, claims = create_api_key(
            user_id, flask.current_app.keypairs[0], expires_in, scope, client_id
        )
        return flask.jsonify(dict(key_id=claims["jti"], api_key=api_key))


class ApiKey(Resource):
    @require_auth_header({"credentials"})
    def delete(self, access_key):
        """
        Delete a key for user

        :param access_key: existing access key that belongs to this user

        :statuscode 204 Success
        :statuscode 403 Forbidden to delete access key
        :statuscode 404 Access key doesn't exist
        """
        user_id = current_token["sub"]

        jti = access_key
        with flask.current_app.db.session as session:
            api_key = (
                session.query(UserRefreshToken)
                .filter_by(jti=jti, userid=user_id)
                .first()
            )
        if not api_key:
            flask.abort(404, "token not found with JTI {} for current user".format(jti))
        blacklist_token(jti, api_key.expires)

        return "", 204


class AccessKey(Resource):
    def post(self):
        """
        Generate an access_token for user given api_key

        :query expires_in: expiration time in seconds, default to 3600, max is 3600

        **Example:**
        .. code-block:: http

               POST /hmac/ HTTP/1.1
               Content-Type: application/json
               Accept: application/json


        .. code-block:: JavaScript

            {
                "access_token": "token_value"
            }
        """
        if (
            flask.request.headers.get("Content-Type")
            == "application/x-www-form-urlencoded"
        ):
            api_key = flask.request.form.get("api_key")
        else:
            try:
                api_key = json.loads(flask.request.data).get("api_key")
            except ValueError:
                api_key = None
        if not api_key:
            flask.abort(400, "Please provide an api_key in payload")

        # TODO Instead of using this endpoint for task tokens, implement oauth2 token exchange
        # (https://datatracker.ietf.org/doc/html/rfc8693): exchange a Refresh Token or API Key for
        # a longer-lived, downscoped access token. authlib doesn’t support token exchange yet
        # (https://github.com/authlib/authlib/issues/821).
        # => https://ctds-planx.atlassian.net/browse/PD-190
        max_ttl = config.get("MAX_ACCESS_TOKEN_TTL", 3600)
        task_token_type = flask.request.args.get("task_token") or None
        if (
            task_token_type
            and task_token_type not in config["ALLOWED_TASK_TOKEN_TYPES"]
        ):
            raise UserError(
                f"Invalid 'task_token' value '{task_token_type}'. Allowed task token types are: {config['ALLOWED_TASK_TOKEN_TYPES']}"
            )
        try:
            expires_in = int(flask.request.args.get("expires_in", max_ttl))
        except ValueError:
            raise UserError(
                f"Invalid 'expires_in' value '{flask.request.args['expires_in']}'"
            )
        if not task_token_type:
            expires_in = min(expires_in, max_ttl)
        else:
            # the classic max token TTL does not apply to task tokens, use the task token TTL
            # instead
            max_task_token_ttl = config["MAX_TASK_TOKEN_TTL"].get(
                task_token_type, max_ttl
            )
            expires_in = min(expires_in, max_task_token_ttl)
            username = get_user_from_claims(
                jwt.decode(
                    api_key,
                    algorithms=["RS256"],
                    options={"verify_signature": False},
                )
            ).username
            if not can_user_get_task_token(task_token_type, expires_in):
                raise Forbidden(
                    f"You do not have access to obtain '{task_token_type}' tokens, or you do not have access to the token lifetime you requested"
                )

        result = create_user_access_token(
            flask.current_app.keypairs[0], api_key, expires_in, audience=task_token_type
        )
        return flask.jsonify(dict(access_token=result))
