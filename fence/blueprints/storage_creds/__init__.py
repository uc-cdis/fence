import flask
from flask_sqlalchemy_session import current_session

from fence.auth import require_auth_header
from fence.blueprints.storage_creds.api import AccessKey, ApiKey, ApiKeyList
from fence.blueprints.storage_creds.google import GoogleCredentialsList
from fence.blueprints.storage_creds.google import GoogleCredentials
from fence.blueprints.storage_creds.other import OtherCredentialsList
from fence.blueprints.storage_creds.other import OtherCredentials
from fence.resources.storage import get_endpoints_descriptions
from fence.restful import RestfulApi
from fence.config import config

ALL_RESOURCES = {
    "/api": "access to CDIS APIs",
    "/ceph": "access to Ceph storage",
    "/cleversafe": "access to cleversafe storage",
    "/aws-s3": "access to AWS S3 storage",
    "/google": "access to Google storage",
}


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
        return flask.jsonify(get_endpoints_descriptions(services, current_session))

    return blueprint
