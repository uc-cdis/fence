import flask
from flask_restful import Resource

from fence.auth import require_auth_header
from fence.auth import current_token
from userdatamodel.models import User


class OtherCredentialsList(Resource):
    """
    For ``/credentials/<provider>`` endpoint.
    """

    @require_auth_header({"credentials"})
    def get(self, provider):
        """
        List access keys for user

        **Example:**
        .. code-block:: http

               POST /credentials/apis/ HTTP/1.1
               Content-Type: application/json
               Accept: application/json

        .. code-block:: JavaScript

            {
                "access_keys":
                [
                    {
                        "access_key": "8DGW9LyC0D4nByoWo6pp",
                    }
                ]
            }
        """
        user_id = current_token["sub"]

        # TODO hopefully we can remove this db call eventually, but
        # StorageManager class requires some updates
        with flask.current_app.db.session as session:
            user = session.query(User).filter_by(id=user_id).first()

        result = flask.current_app.storage_manager.list_keypairs(provider, user)
        keys = {"access_keys": [{"access_key": item["access_key"]} for item in result]}
        result = keys

        return flask.jsonify(result)

    @require_auth_header({"credentials"})
    def post(self, provider):
        """
        Generate a keypair for user

        **Example:**
        .. code-block:: http

               POST /credentials/cdis/?expires_in=3600 HTTP/1.1
               Content-Type: application/json
               Accept: application/json

        .. code-block:: JavaScript

            {
                "access_key": "8DGW9LyC0D4nByoWo6pp",
                "secret_key": "1lnkGScEH8Vr4EC6QnoqLK1PqRWPNqIBJkH6Vpgx"
            }
        """
        user_id = current_token["sub"]

        # TODO hopefully we can remove this db call eventually, but
        # StorageManager class requires some updates
        with flask.current_app.db.session as session:
            user = session.query(User).filter_by(id=user_id).first()

        return flask.jsonify(
            flask.current_app.storage_manager.create_keypair(provider, user)
        )


class OtherCredentials(Resource):
    def delete(self, provider, access_key):
        """
        Delete a keypair for user

        :param access_key: existing access key that belongs to this user

        :statuscode 204 Success
        :statuscode 403 Forbidden to delete access key
        :statuscode 404 Access key doesn't exist
        """
        user_id = current_token["sub"]

        # TODO hopefully we can remove this db call eventually, but
        # StorageManager class requires some updates
        with flask.current_app.db.session as session:
            user = session.query(User).filter_by(id=user_id).first()

        flask.current_app.storage_manager.delete_keypair(provider, user, access_key)

        return "", 204
