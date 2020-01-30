from datetime import datetime
import flask
import re
import time
from distutils.util import strtobool
from flask_restful import Resource
from flask_sqlalchemy_session import current_session

from cirrus import GoogleCloudManager
from cirrus.config import config as cirrus_config

from fence.config import config
from fence.auth import require_auth_header
from fence.auth import current_token
from fence.errors import UserError
from fence.models import GoogleServiceAccountKey
from fence.resources.google.utils import (
    add_custom_service_account_key_expiration,
    create_google_access_key,
    get_service_account,
    get_or_create_service_account,
    get_or_create_proxy_group_id,
    give_service_account_billing_access_if_necessary,
)
from fence.utils import get_valid_expiration_from_request

from cdislogging import get_logger

logger = get_logger(__name__)


class GoogleCredentialsList(Resource):
    """
    For ``/credentials/google`` endpoint.
    """

    @require_auth_header({"google_credentials"})
    def get(self):
        """
        List access keys for user

        **Example:**
        .. code-block:: http

               POST /credentials/apis/ HTTP/1.1
               Content-Type: application/json
               Accept: application/json

        Info from Google API /serviceAccounts/<account>/keys endpoint
        but get the expiration time from our DB

        .. code-block:: JavaScript

            {
                "access_keys":
                [
                    {
                        "keyAlgorithm": enum(ServiceAccountKeyAlgorithm),
                        "validBeforeTime": string,
                        "name": string,
                        "validAfterTime": string,
                    },
                    ...
                ]
            }

        """
        client_id = current_token.get("azp") or None
        user_id = current_token["sub"]
        username = current_token.get("context", {}).get("user", {}).get("name")

        with GoogleCloudManager() as g_cloud_manager:
            proxy_group_id = get_or_create_proxy_group_id()
            service_account = get_or_create_service_account(
                client_id=client_id,
                user_id=user_id,
                username=username,
                proxy_group_id=proxy_group_id,
            )

            keys = g_cloud_manager.get_service_account_keys_info(service_account.email)

            # replace Google's expiration date by the one in our DB
            reg = re.compile(".+\/keys\/(.+)")  # get key_id from xx/keys/key_id
            for i, key in enumerate(keys):
                key_id = reg.findall(key["name"])[0]
                db_entry = (
                    current_session.query(GoogleServiceAccountKey)
                    .filter_by(service_account_id=service_account.id)
                    .filter_by(key_id=key_id)
                    .first()
                )

                if db_entry:
                    # convert timestamp to date - use the same format as Google API
                    exp_date = datetime.utcfromtimestamp(db_entry.expires).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                    key["validBeforeTime"] = exp_date

                # the key exists in Google but not in our DB. This should not
                # happen! Delete the key from Google
                else:
                    keys.pop(i)
                    logger.warning(
                        "No GoogleServiceAccountKey entry was found in the fence database for service account name {} for key_id {}, which exists in Google. It will now be deleted from Google.".format(
                            username, key_id
                        )
                    )
                    with GoogleCloudManager() as g_cloud:
                        g_cloud.delete_service_account_key(
                            service_account.email, key_id
                        )

            result = {"access_keys": keys}

        return flask.jsonify(result)

    @require_auth_header({"google_credentials"})
    def post(self):
        """
        Generate a keypair for user

        **Example:**
        .. code-block:: http

               POST /credentials/cdis/?expires_in=3600 HTTP/1.1
               Content-Type: application/json
               Accept: application/json

        (JSON key in Google Credentials File format)

        .. code-block:: JavaScript

            {
                "type": "service_account",
                "project_id": "project-id",
                "private_key_id": "some_number",
                "private_key": "-----BEGIN PRIVATE KEY-----\n....
                =\n-----END PRIVATE KEY-----\n",
                "client_email": "<api-name>api@project-id.iam.gserviceaccount.com",
                "client_id": "...",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://accounts.google.com/o/oauth2/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/...<api-name>api%40project-id.iam.gserviceaccount.com"
            }
        """
        user_id = current_token["sub"]
        client_id = current_token.get("azp") or None
        proxy_group_id = get_or_create_proxy_group_id()
        username = current_token.get("context", {}).get("user", {}).get("name")

        r_pays_project = flask.request.args.get("userProject", None)

        key, service_account = create_google_access_key(
            client_id, user_id, username, proxy_group_id
        )

        if config["ENABLE_AUTOMATIC_BILLING_PERMISSION_SA_CREDS"]:
            give_service_account_billing_access_if_necessary(
                key,
                r_pays_project,
                default_billing_project=config["BILLING_PROJECT_FOR_SA_CREDS"],
            )

        if client_id is None:
            self.handle_user_service_account_creds(key, service_account)

        return flask.jsonify(key)

    @require_auth_header({"google_credentials"})
    def delete(self):
        """
        .. http:get: /google/
        Delete keypair(s) for user
        ?all=true must be specified

        True values are y, yes, t, true, on and 1; false values are n, no, f, false, off and 0

        :statuscode 204 Success
        :statuscode 403 Forbidden to delete access key
        :statuscode 405 Method Not Allowed if ?all=true is not included
        """
        user_id = current_token["sub"]

        try:
            all_arg = strtobool(flask.request.args.get("all", "false").lower())
        except ValueError:
            all_arg = False

        if not all_arg:
            flask.abort(
                405,
                "Please include ?all=true to confirm deletion of ALL Google Service account keys.",
            )

        with GoogleCloudManager() as g_cloud:
            client_id = current_token.get("azp") or None
            service_account = get_service_account(client_id, user_id)

            if service_account:
                keys_for_account = g_cloud.get_service_account_keys_info(
                    service_account.email
                )

                # Only delete the key if is owned by current client's SA
                all_client_keys = [
                    key["name"].split("/")[-1] for key in keys_for_account
                ]

                for key in all_client_keys:
                    _delete_service_account_key(g_cloud, service_account.email, key)
            else:
                flask.abort(404, "Could not find service account for current user.")

        return "", 204

    def handle_user_service_account_creds(self, key, service_account):
        """
        Add the service account creds for the user into our db. Actual
        Oauth Client SAs are handled separately. This function assigns
        the same expiration to the user's generated key but the mechanism
        for expiration uses our db instead of checking google directly.

        See fence-create scripting functions for expiration logic.

        The reason for this difference is due to the fact that fence itself
        uses the user's primary service account for url signing (in addition
        to the user themselves). Since the expirations are different, a
        different mechanism than the Client SAs was required.
        """
        # requested time (in seconds) during which the access key will be valid
        # x days * 24 hr/day * 60 min/hr * 60 s/min = y seconds
        expires_in = cirrus_config.SERVICE_KEY_EXPIRATION_IN_DAYS * 24 * 60 * 60
        requested_expires_in = get_valid_expiration_from_request()
        if requested_expires_in:
            expires_in = min(expires_in, requested_expires_in)

        expiration_time = int(time.time()) + int(expires_in)
        key_id = key.get("private_key_id")
        add_custom_service_account_key_expiration(
            key_id, service_account.id, expires=expiration_time
        )


class GoogleCredentials(Resource):
    @require_auth_header({"google_credentials"})
    def delete(self, access_key):
        """
        .. http:get: /google/(string: access_key)
        Delete keypair(s) for user

        :param access_key: existing access key that belongs to this user

        :statuscode 204 Success
        :statuscode 403 Forbidden to delete access key
        :statuscode 404 Access key doesn't exist
        """
        user_id = current_token["sub"]
        with GoogleCloudManager() as g_cloud:
            client_id = current_token.get("azp") or None
            service_account = get_service_account(client_id, user_id)

            if service_account:
                keys_for_account = g_cloud.get_service_account_keys_info(
                    service_account.email
                )

                # Only delete the key if is owned by current client's SA
                all_client_keys = [
                    key["name"].split("/")[-1] for key in keys_for_account
                ]

                if access_key in all_client_keys:
                    _delete_service_account_key(
                        g_cloud, service_account.email, access_key
                    )
                else:
                    flask.abort(
                        404,
                        "Could not delete key "
                        + access_key
                        + ". Not found for current user.",
                    )
            else:
                flask.abort(404, "Could not find service account for current user.")

        return "", 204


def _delete_service_account_key(g_cloud, service_account_id, access_key):
    """
    Internal function for deleting a given key for a service account, also
    removes entry from our db if it exists
    """
    try:
        response = g_cloud.delete_service_account_key(service_account_id, access_key)
    except Exception:
        logger.debug(
            "Deleting service account {} key {} from Google FAILED. Response: {}. "
            "We did NOT delete it from our DB either.".format(
                service_account_id, access_key, str(response)
            )
        )
        raise

    logger.debug(
        "Deleting service account {} key {} from Google succeeded. Response: {}".format(
            service_account_id, access_key, str(response)
        )
    )

    db_entry = (
        current_session.query(GoogleServiceAccountKey)
        .filter_by(key_id=access_key)
        .first()
    )
    if db_entry:
        current_session.delete(db_entry)
        current_session.commit()

    logger.info(
        "Removed Google Service Account {} Key with ID: {} from Google and our DB.".format(
            service_account_id, access_key
        )
    )
