from flask_sqlalchemy_session import current_session
import flask
from flask_restful import Api

from fence.auth import require_auth_header
from fence.resources.storage import get_endpoints_descriptions
from fence.blueprints.storage_creds.google import GoogleCredentialsList
from fence.blueprints.storage_creds.google import GoogleCredentials
from fence.blueprints.storage_creds.cdis import CdisApiKeyList
from fence.blueprints.storage_creds.cdis import CdisApiKey
from fence.blueprints.storage_creds.cdis import CdisAccessKey
from fence.blueprints.storage_creds.other import OtherCredentialsList
from fence.blueprints.storage_creds.other import OtherCredentials

ALL_RESOURCES = {
    '/cdis': 'access to CDIS APIs',
    '/ceph': 'access to Ceph storage',
    '/cleversafe': 'access to cleversafe storage',
    '/aws-s3': 'access to AWS S3 storage',
    '/google': 'access to Google storage'
}


def make_creds_blueprint():
    blueprint = flask.Blueprint('credentials', __name__)
    blueprint_api = Api(blueprint)

    blueprint_api.add_resource(
        GoogleCredentialsList, '/google', strict_slashes=False
    )
    blueprint_api.add_resource(
        GoogleCredentials, '/google/<access_key>', strict_slashes=False
    )
    blueprint_api.add_resource(
        CdisApiKeyList, '/cdis', strict_slashes=False
    )
    blueprint_api.add_resource(
        CdisApiKey, '/cdis/<access_key>', strict_slashes=False
    )
    blueprint_api.add_resource(
        CdisAccessKey, '/cdis/access_token', strict_slashes=False
    )
    blueprint_api.add_resource(
        OtherCredentialsList, '/<provider>', strict_slashes=False
    )
    blueprint_api.add_resource(
        OtherCredentials, '/<provider>/<access_key>', strict_slashes=False
    )

    @blueprint.route('/', methods=['GET'])
    @require_auth_header({'credentials'})
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
                "/cdis": "access to CDIS APIs",
                "/ceph": "access to Ceph storage",
                "/cleversafe": "access to cleversafe storage",
                "/aws-s3", "access to AWS S3 storage"
                "/google", "access to Google Cloud storage"
            }
        """
        services = flask.current_app.config.get('STORAGES', [])
        return flask.jsonify(get_endpoints_descriptions(
            services, current_session))

    return blueprint
