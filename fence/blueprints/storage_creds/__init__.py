import json

from cdislogging import get_logger
import flask
from flask import current_app

from fence.auth import require_auth_header
from fence.blueprints.storage_creds.api import AccessKey, ApiKey, ApiKeyList
from fence.blueprints.storage_creds.google import GoogleCredentialsList
from fence.blueprints.storage_creds.google import GoogleCredentials
from fence.blueprints.storage_creds.other import OtherCredentialsList
from fence.blueprints.storage_creds.other import OtherCredentials
from fence.errors import Unauthorized
from fence.jwt.blacklist import blacklist_encoded_token, is_token_blacklisted
from fence.jwt.errors import JWTError
from fence.jwt.utils import get_jwt_header
from fence.resources.storage import get_endpoints_descriptions
from fence.restful import RestfulApi
from fence.config import config


logger = get_logger(__name__)


ALL_RESOURCES = {
    "/api": "access to CDIS APIs",
    "/ceph": "access to Ceph storage",
    "/cleversafe": "access to cleversafe storage",
    "/aws-s3": "access to AWS S3 storage",
    "/google": "access to Google storage",
}


def get_token_from_body_or_header():
    """
    Return the value of the request body `token` field if present.
    Fall back to the request's Authorization header otherwise.
    """
    try:
        body = json.loads(flask.request.data)
    except Exception:
        body = {}
    encoded_token = body.get("token")
    if not encoded_token:
        encoded_token = get_jwt_header()
    return encoded_token


def make_creds_blueprint():
    blueprint = flask.Blueprint("credentials", __name__)
    blueprint_api = RestfulApi(blueprint)

    blueprint_api.add_resource(GoogleCredentialsList, "/google", strict_slashes=False)
    blueprint_api.add_resource(
        GoogleCredentials, "/google/<access_key>", strict_slashes=False
    )

    # TODO: REMOVE DEPRECATED /cdis ENDPOINTS
    # temporarily leaving them here to give time for users to make switch
    blueprint_api.add_resource(ApiKeyList, "/api", "/cdis", strict_slashes=False)
    blueprint_api.add_resource(
        ApiKey, "/api/<access_key>", "/cdis/<access_key>", strict_slashes=False
    )
    blueprint_api.add_resource(
        AccessKey, "/api/access_token", "/cdis/access_token", strict_slashes=False
    )

    blueprint_api.add_resource(
        OtherCredentialsList, "/<provider>", strict_slashes=False
    )
    blueprint_api.add_resource(
        OtherCredentials, "/<provider>/<access_key>", strict_slashes=False
    )

    @blueprint.route("/", methods=["GET"])
    @require_auth_header({"credentials"})
    def list_sources():
        """
        List different resources user can have credentials

        **Example:**
        .. code-block:: http

               GET /credentials/ HTTP/1.1
               Content-Type: application/json
               Accept: application/json

        .. code-block:: JavaScript

            {
                "/api": "access to CDIS APIs",
                "/ceph": "access to Ceph storage",
                "/cleversafe": "access to cleversafe storage",
                "/aws-s3", "access to AWS S3 storage"
                "/google", "access to Google Cloud storage"
            }
        """
        services = set(
            [
                info.get("backend")
                for _, info in config["STORAGE_CREDENTIALS"].items()
                if info.get("backend")
            ]
        )
        return flask.jsonify(
            get_endpoints_descriptions(services, current_app.scoped_session())
        )

    @blueprint.route("/token/revoke", methods=["POST"])
    @require_auth_header()
    def revoke_token():
        """
        Can be used to revoke any revocable token.
        """
        blacklist_encoded_token(get_token_from_body_or_header())
        return "", 200

    @blueprint.route("/token/blacklisted", methods=["POST"])
    def check_if_token_blacklisted():
        """
        Check if a token is blacklisted/revoked. Return 403 if it is.

        If the token cannot be parsed, assume it is not blacklisted and that the invalid
        token will be rejected by downstream APIs.

        This endpoint is leveraged by revproxy to block requests from blacklisted tokens.
        """
        try:
            claims, is_blacklisted = is_token_blacklisted(
                get_token_from_body_or_header()
            )
        except (Unauthorized, JWTError) as e:
            logger.warning(
                f"No provided token, or provided token is invalid: `{e}`. Token not blacklisted."
            )
            return "", 200

        if is_blacklisted:
            logger.warning(
                f'Blocking attempt to use a blacklisted token. jti={claims.get("jti")}; azp={claims.get("azp")}; sub={claims.get("sub")}; username={claims.get("context", {}).get("user", {}).get("name")}'
            )
            return "Token is blacklisted", 403
        return "", 200

    return blueprint
