import os
import json
from urllib.parse import unquote
from enum import Enum
import time

import flask
from flask_restful import Resource

from cirrus import GoogleCloudManager
from cirrus.errors import CirrusNotFound
from cirrus.google_cloud.errors import GoogleAPIError

from fence.auth import current_token, require_auth_header
from fence.restful import RestfulApi
from fence.config import config
from fence.errors import UserError, NotFound, Unauthorized, Forbidden
from fence.resources.google.validity import GoogleProjectValidity
from fence.resources.google.access_utils import (
    is_user_member_of_all_google_projects,
    is_user_member_of_google_project,
    get_registered_service_account_from_email,
    get_service_account_email,
    force_remove_service_account_from_access,
    force_delete_service_account,
    extend_service_account_access,
    patch_user_service_account,
    get_project_ids_from_project_auth_ids,
    add_user_service_account_to_google,
    add_user_service_account_to_db,
    get_google_access_groups_for_service_account,
)
from fence.resources.google.utils import (
    get_monitoring_service_account_email,
    get_registered_service_accounts,
    get_project_access_from_service_accounts,
)
from fence.models import UserServiceAccount
from fence.utils import get_valid_expiration_from_request
from flask_sqlalchemy_session import current_session


class ValidationErrors(str, Enum):
    MONITOR_NOT_FOUND = "monitor_not_found"
    UNAUTHORIZED_USER = "unauthorized_user"
    POLICY_NOT_ACCESSIBLE = "policy_not_accessible"
    UNAUTHORIZED = "unauthorized"
    PROJECT_NOT_FOUND = "project_not_found"
    GOOGLE_PROJECT_NOT_INCLUDED = "google_project_not_included"


def make_google_blueprint():
    """
    Return:
        flask.Blueprint: the blueprint used for ``/google`` endpoints
    """
    blueprint = flask.Blueprint("google", __name__)
    blueprint_api = RestfulApi(blueprint)

    blueprint_api.add_resource(
        GoogleServiceAccountRoot, "/service_accounts", strict_slashes=False
    )

    blueprint_api.add_resource(
        GoogleBillingAccount, "/billing_projects", strict_slashes=False
    )

    blueprint_api.add_resource(
        GoogleServiceAccountDryRun,
        "/service_accounts/_dry_run/<id_>",
        strict_slashes=False,
    )

    blueprint_api.add_resource(
        GoogleServiceAccount, "/service_accounts/<id_>", strict_slashes=False
    )

    return blueprint


class GoogleServiceAccountRegistration(object):
    """
    Data class for certain functions in /google endpoints. Represents a registered
    service account and it's basic information. You can optionally include a user_id,
    which represents which user is interacting w/ or requesting changes for the
    given registered service account.
    """

    def __init__(self, email, project_access, google_project_id, user_id=None):
        """
        Return a GoogleServiceAccountRegistration instance

        Args:
            email(str): email address of
                service account to be registered
            google_project_id(str): unique-id of google project
            project_access(List[str]): list of project auth-ids which
                identify which projects the service account should have
                access to
            user_id (str, optional): Description
        """
        self.email = email
        self.project_access = project_access
        self.google_project_id = google_project_id
        self.user_id = user_id


class GoogleBillingAccount(Resource):
    def get(self):
        """
        Get the configured default Google billing projects if it exists.
        """
        return {
            "signed_urls": {"project_id": config["BILLING_PROJECT_FOR_SIGNED_URLS"]},
            "temporary_service_account_credentials": {
                "project_id": config["BILLING_PROJECT_FOR_SA_CREDS"]
            },
        }


class GoogleServiceAccountRoot(Resource):
    @require_auth_header({"google_service_account"})
    def post(self):
        """
        Register a new service account
        """
        user_id = current_token["sub"]
        payload = flask.request.get_json(silent=True) or {}

        project_access = payload.get("project_access")

        if len(project_access) > config["SERVICE_ACCOUNT_LIMIT"]:
            response = {
                "success": False,
                "errors": {
                    "service_account_limit": {
                        "status": 400,
                        "error": "project_limit",
                        "error_description": "Exceeded Allowable Number of Projects. Maximum {} Projects allowed per account.".format(
                            config["SERVICE_ACCOUNT_LIMIT"]
                        ),
                    }
                },
            }

            return response, 400

        sa = GoogleServiceAccountRegistration(
            email=payload.get("service_account_email"),
            project_access=project_access,
            google_project_id=payload.get("google_project_id"),
            user_id=user_id,
        )

        return self._post_new_service_account(sa)

    @require_auth_header({"google_service_account"})
    def get(self):
        google_projects = flask.request.args.get("google_project_ids")

        if not google_projects:
            return (
                "Getting service accounts is only supported with the "
                "google_project_ids query param at the moment.",
                400,
            )

        # if not monitor, we should assume google project ids and parse
        google_project_ids = [
            project_id.strip() for project_id in unquote(google_projects).split(",")
        ]

        # check if user has permission to get service accounts
        # for these projects
        user_id = current_token["sub"]
        authorized = is_user_member_of_all_google_projects(user_id, google_project_ids)

        if not authorized:
            return (
                "Could not determine if user is a member on all the "
                "provided Google project IDs.",
                403,
            )

        service_accounts = self._get_project_service_accounts(
            google_project_ids=google_project_ids
        )

        response = {"service_accounts": service_accounts}

        return response, 200

    def _post_new_service_account(self, sa):
        """
        Return response tuple for registering a new service account

        Args:
            sa (
                fence.resources.google.service_account.GoogleServiceAccountRegistration
            ): the service account object with its email, project_access, a google project,
               and optionally a user who is attempting to modify/add

        Returns:
            tuple(dict, int): (response_data, http_status_code)
        """
        error_response = _get_service_account_error_status(sa)

        if error_response.get("success") is not True:
            return error_response, 400

        sa_exists = (
            current_session.query(UserServiceAccount).filter_by(email=sa.email).all()
        )

        if sa_exists:
            error_response["success"] = False
            error_response["errors"]["service_account_email"] = {
                "status": 409,
                "error": "Conflict",
                "error_description": "Service Account already registered.",
            }
            return error_response, 400

        new_service_account = self._register_new_service_account(sa)

        return new_service_account, 200

    def _register_new_service_account(self, sa):
        """
        Add service account and related entries to database and add
        service account to google bucket access groups

        WARNING: this assumes that the project_access provided are all
        valid Project.auth_ids, currently checked before this is called
        in validity checking

        Args:
            sa (
                fence.resources.google.service_account.GoogleServiceAccountRegistration
            ): the service account object with its email, project_access, a google project,
               and optionally a user who is attempting to modify/add

        Return:
            (dict): dictionary representing service account object
        """
        with GoogleCloudManager(sa.google_project_id) as google_project:
            g_service_account = google_project.get_service_account(sa.email)

        db_service_account = UserServiceAccount(
            google_unique_id=g_service_account.get("uniqueId"),
            email=g_service_account.get("email"),
            google_project_id=sa.google_project_id,
        )

        current_session.add(db_service_account)
        current_session.commit()

        project_ids = get_project_ids_from_project_auth_ids(
            current_session, sa.project_access
        )

        add_user_service_account_to_db(current_session, project_ids, db_service_account)

        add_user_service_account_to_google(
            current_session, project_ids, sa.google_project_id, db_service_account
        )

        return {
            "service_account_email": g_service_account.get("email"),
            "google_project_id": g_service_account.get("projectId"),
            "project_access": sa.project_access,
        }

    def _get_project_service_accounts(self, google_project_ids):
        """
        Return a list of service accounts for the given Google Cloud
        Project IDs.

        WARNING: NO AUTHORIZATION CHECK DONE HERE. This will blindly return
                 all service accounts for the given projects.

        Args:
            google_project_ids (List(str)): List of unique google project ids

        Raises:
            List(dict): List of service accounts

            Example:
            {
              "service_accounts": [
                {
                  "service_account_email": "string",
                  "google_project_id": "string",
                  "project_access": [
                    "string"
                  ],
                  "project_access_exp": 0
                }
              ]
            }
        """
        all_service_accounts = []
        for google_project_id in google_project_ids:
            output_service_accounts = []
            project_service_accounts = get_registered_service_accounts(
                google_project_id
            )

            for project_sa in project_service_accounts:
                project_access = get_project_access_from_service_accounts([project_sa])

                # need to determine expiration by getting the access groups
                # and then checking the expiration for each of them
                bucket_access_groups = get_google_access_groups_for_service_account(
                    project_sa
                )

                sa_to_gbags = []
                for gbag in bucket_access_groups:
                    sa_to_gbags.extend(gbag.to_access_groups)

                expirations = [
                    sa_to_gbag.expires
                    for sa_to_gbag in sa_to_gbags
                    if sa_to_gbag.service_account_id == project_sa.id
                ]

                output_sa = {
                    "service_account_email": project_sa.email,
                    "google_project_id": project_sa.google_project_id,
                    "project_access": [project.auth_id for project in project_access],
                    "project_access_exp": min(expirations or [0]),
                }
                output_service_accounts.append(output_sa)

            all_service_accounts.extend(output_service_accounts)

        return all_service_accounts


class GoogleServiceAccount(Resource):
    @require_auth_header({"google_service_account"})
    def get(self, id_):
        """
        Get registered service account(s) and their access expiration.

        Args:
            id_ (str): either "monitor" or a comma-delimited list of Google
                      Project IDs to get list of service accounts for.

                      Specifying "monitor" will return the service account
                      email used for monitoring purposes.
        """
        if id_ == "monitor":
            return self._get_monitoring_service_account_response()

        return ("Currently getting a specific service account is not supported.", 400)

    @require_auth_header({"google_service_account"})
    def post(self, id_):
        """
        Dry run for registering a new service account

        Args:
            id_ (str): Must be "_dry_run", otherwise, error
        """
        if id_ != "_dry_run":
            raise UserError("Cannot post with account id_.")

        user_id = current_token["sub"]
        payload = flask.request.get_json(silent=True) or {}

        project_access = payload.get("project_access")

        if len(project_access) > config["SERVICE_ACCOUNT_LIMIT"]:
            response = {
                "success": False,
                "errors": {
                    "service_account_limit": {
                        "status": 400,
                        "error": "project_limit",
                        "error_description": "Exceeded Allowable Number of Projects. Maximum {} Projects allowed per account.".format(
                            config["SERVICE_ACCOUNT_LIMIT"]
                        ),
                    }
                },
            }

            return response, 400

        sa = GoogleServiceAccountRegistration(
            email=payload.get("service_account_email"),
            project_access=project_access,
            google_project_id=payload.get("google_project_id"),
            user_id=user_id,
        )

        error_response = _get_service_account_error_status(sa)

        sa_exists = (
            current_session.query(UserServiceAccount).filter_by(email=sa.email).all()
        )

        if sa_exists:
            error_response["success"] = False
            error_response["errors"]["service_account_email"] = {
                "status": 409,
                "error": "Conflict",
                "error_description": "Service Account already registered.",
            }

        if error_response.get("success") is True:
            status = 200
        else:
            status = 400

        return error_response, status

    @require_auth_header({"google_service_account"})
    def patch(self, id_):
        """
        Update a service account

        Args:
            id_ (str): Google service account identifier to update
        """
        sa = _get_service_account_for_patch(id_)
        if type(sa) != GoogleServiceAccountRegistration:
            return sa
        error_response = _get_patched_service_account_error_status(id_, sa)
        if error_response.get("success") is not True:
            return error_response, 400
        resp, status_code = self._update_service_account_permissions(sa)
        if status_code != 200:
            return resp, status_code

        # extend access to all datasets
        extend_service_account_access(sa.email)

        return "", 204

    @require_auth_header({"google_service_account"})
    def delete(self, id_):
        """
        Delete a service account

        Args:
            id_ (str): Google service account email to delete
        """
        user_id = current_token["sub"]

        service_account_email = get_service_account_email(id_)
        registered_service_account = get_registered_service_account_from_email(
            service_account_email
        )
        if not registered_service_account:
            raise NotFound(
                "Could not find a registered service account from given email {}".format(
                    service_account_email
                )
            )

        google_project_id = registered_service_account.google_project_id

        # check if user has permission to delete the service account
        with GoogleCloudManager(google_project_id) as gcm:
            authorized = is_user_member_of_google_project(user_id, gcm)

        if not authorized:
            return (
                'User "{}" does not have permission to delete the provided '
                'service account "{}".'.format(user_id, id_),
                403,
            )

        return self._delete(id_)

    def _get_monitoring_service_account_response(self):
        """
        Return a response that includes our app's service account used
        for monitoring user's Google projects.

        Returns:
            tuple(dict, int): (response_data, http_status_code)
        """
        monitoring_account_email = get_monitoring_service_account_email()
        if not monitoring_account_email:
            error = (
                "No monitoring service account. Fence is not currently "
                "configured to support user-registration of service accounts."
            )
            return {"message": error}, 404

        response = {"service_account_email": monitoring_account_email}
        return response, 200

    def _update_service_account_permissions(self, sa):
        """
        Update the given service account's permissions.

        WARNING: NO AUTHORIZATION CHECK DONE HERE. This will blindly update
                 given service account.

        Args:
            sa (
                fence.resources.google.service_account.GoogleServiceAccountRegistration
            ): the service account object with its email, project_access, a google project,
               and optionally a user who is attempting to modify/add
        """
        try:
            patch_user_service_account(
                sa.google_project_id, sa.email, sa.project_access
            )
        except CirrusNotFound as exc:
            return (
                "Can not update the service accout {}. Detail {}".format(sa.email, exc),
                404,
            )
        except GoogleAPIError as exc:
            return (
                "Can not update the service accout {}. Detail {}".format(sa.email, exc),
                400,
            )
        except Exception:
            return ("Can not update the service account {}".format(sa.email), 500)

        return ("Successfully update service account  {}".format(sa.email), 200)

    @classmethod
    def _delete(self, id_):
        """
        Delete the given service account from our db and Google if it
        exists.

        WARNING: NO AUTHORIZATION CHECK DONE HERE. This will blindly delete
                 given service account.

        Args:
            account_id (str): Google service account identifier
        """

        service_account_email = get_service_account_email(id_)
        registered_service_account = get_registered_service_account_from_email(
            service_account_email
        )

        google_project_id = registered_service_account.google_project_id

        try:
            force_remove_service_account_from_access(
                service_account_email, google_project_id
            )
            force_delete_service_account(service_account_email)
        except CirrusNotFound as exc:
            return (
                "Can not remove the service accout {}. Detail {}".format(id_, exc),
                404,
            )
        except GoogleAPIError as exc:
            return (
                "Can not remove the service accout {}. Detail {}".format(id_, exc),
                400,
            )
        except Exception:
            return (" Can not delete the service account {}".format(id_), 500)

        return "Successfully delete service account  {}".format(id_), 200


class GoogleServiceAccountDryRun(Resource):
    @require_auth_header({"google_service_account"})
    def patch(self, id_):
        """
        Dry run (test updating a service account without actually doing it)

        Args:
            id_ (str): Google service account identifier to update
        """
        sa = _get_service_account_for_patch(id_)

        if type(sa) != GoogleServiceAccountRegistration:
            return sa

        error_response = _get_patched_service_account_error_status(id_, sa)

        # this is where it actually does stuff in the non-dryrun endpoint

        if error_response.get("success") is True:
            status = 200
        else:
            status = 400

        return error_response, status


def _get_service_account_for_patch(id_):
    user_id = current_token["sub"]

    service_account_email = get_service_account_email(id_)
    registered_service_account = get_registered_service_account_from_email(
        service_account_email
    )
    if not registered_service_account:
        raise NotFound(
            "Could not find a registered service account from given email {}".format(
                service_account_email
            )
        )

    payload = flask.request.get_json(silent=True) or {}

    # check if the user requested to update more than project_access
    project_access = payload.pop("project_access", None)

    # if they're trying to patch more fields, error out, we only support the above
    if payload:
        raise Forbidden("Cannot update provided fields: {}".format(payload))

    # if the field is not provided at all, use service accounts current access
    # NOTE: the user can provide project_access=[] to remove all datasets so checking
    #       `if not project_access` here will NOT work
    #
    #       In other words, to extend access you don't provide the field. To remove all
    #       access you provide it as an empty list
    if project_access is None:
        project_access = [
            access_privilege.project.auth_id
            for access_privilege in registered_service_account.access_privileges
        ]

    if len(project_access) > config["SERVICE_ACCOUNT_LIMIT"]:
        response = {
            "success": False,
            "errors": {
                "service_account_limit": {
                    "status": 400,
                    "error": "project_limit",
                    "error_description": "Exceeded Allowable Number of Projects. Maximum {} Projects allowed per account.".format(
                        config["SERVICE_ACCOUNT_LIMIT"]
                    ),
                }
            },
        }

        return response, 400

    google_project_id = registered_service_account.google_project_id

    return GoogleServiceAccountRegistration(
        service_account_email, project_access, google_project_id, user_id=user_id
    )


def _get_patched_service_account_error_status(id_, sa):
    """
    Get error status for attempting to patch given service account with access.

    Args:
        id_ (str): Google service account identifier to update
        sa (
            fence.resources.google.service_account.GoogleServiceAccountRegistration
        ): the service account object with its email, project_access, a google project,
           and optionally a user who is attempting to modify/add
    """
    # check if user has permission to update the service account
    authorized = is_user_member_of_all_google_projects(
        sa.user_id, [sa.google_project_id]
    )
    if not authorized:
        msg = (
            'User "{}" does not have permission to update the provided '
            'service account "{}".'.format(sa.user_id, id_)
        )
        raise Unauthorized(msg)

    error_response = _get_service_account_error_status(sa)

    return error_response


def _get_service_account_error_status(sa):
    """
    Get a dictionary describing any errors that will occur if attempting
    to give service account specified permissions fails.

    Args:
        sa (
            fence.resources.google.service_account.GoogleServiceAccountRegistration
        ): the service account object with its email, project_access, a google project,
           and optionally a user who is attempting to modify/add

    Returns:
        dict: error information if unsuccessful, { "success": True } otherwise

        Example:
        {
            "success": False,
            "errors": {
                "service_account_email": {
                    "status": 200,
                    "error": None,
                    "error_description": None
                },
                "google_project_id": {
                    "status": 200,
                    "error": None,
                    "error_description": None
                },
                "project_access": {
                    "projectA": {
                        "status": 200,
                        "error": None,
                        "error_description": None
                    },
                    "projectB": {
                        "status": 403,
                        "error": "unauthorized",
                        "error_description": "Not all users have access requested"
                    }
                },
                "expires_in": {
                    "status": 400,
                    "error": "user_error",
                    "error_description": "expires_in must be a positive integer"
                }
            }
        }
    """
    response = {
        "success": False,
        "errors": {
            "service_account_email": None,
            "google_project_id": None,
            "project_access": None,
            "expires_in": {"status": 200, "error": None, "error_description": None},
        },
    }

    try:
        get_valid_expiration_from_request()
    except UserError as e:
        response["errors"]["expires_in"] = {
            "status": e.code,
            "error": "user_error",
            "error_description": e.message,
        }

    project_validity = GoogleProjectValidity(
        google_project_id=sa.google_project_id,
        new_service_account=sa.email,
        new_service_account_access=sa.project_access,
        user_id=sa.user_id,
    )
    project_validity.check_validity(early_return=False)

    response["errors"]["google_project_id"] = _get_google_project_id_error_status(
        project_validity
    )

    response["errors"][
        "service_account_email"
    ] = _get_service_account_email_error_status(project_validity)

    response["errors"]["project_access"] = _get_project_access_error_status(
        project_validity
    )

    # if we cannot find the monitoring service account, the other checks statuses should
    # not be 200 and should be populated with relevant information
    if (
        response["errors"]["google_project_id"]["error"]
        == ValidationErrors.MONITOR_NOT_FOUND
    ):
        if response["errors"]["service_account_email"].get("status") == 200:
            response["errors"]["service_account_email"]["status"] = 400
            response["errors"]["service_account_email"][
                "error"
            ] = ValidationErrors.MONITOR_NOT_FOUND
            response["errors"]["service_account_email"]["error_description"] = (
                "Fence's monitoring service account was not found on the project so we "
                "were unable to complete the necessary validation checks."
            )
        if response["errors"]["project_access"].get("status") == 200:
            response["errors"]["project_access"]["status"] = 400
            response["errors"]["project_access"][
                "error"
            ] = ValidationErrors.MONITOR_NOT_FOUND
            response["errors"]["project_access"]["error_description"] = (
                "Fence's monitoring service account was not found on the project so we "
                "were unable to complete the necessary validation checks."
            )

    # all statuses must be 200 to be successful
    if (
        response["errors"]["service_account_email"].get("status") == 200
        and response["errors"]["google_project_id"].get("status") == 200
        and response["errors"]["project_access"].get("status") == 200
        and response["errors"]["expires_in"].get("status") == 200
    ):
        response["success"] = True

    return response


def _get_service_account_email_error_status(validity_info):
    service_accounts_validity = validity_info.get("new_service_account")

    response = {
        "status": 200,
        "error": None,
        "error_description": "",
        "service_account_validity": {},
    }

    for sa_account_id, sa_validity in service_accounts_validity:
        if sa_account_id == validity_info.new_service_account:
            if not sa_validity:
                if sa_validity["policy_accessible"]:
                    response["status"] = 403
                    response["error"] = ValidationErrors.UNAUTHORIZED
                    response[
                        "error_description"
                    ] = "Service account requested for registration is invalid."
                else:
                    response["status"] = 404
                    response["error"] = ValidationErrors.POLICY_NOT_ACCESSIBLE
                    response[
                        "error_description"
                    ] = "Either the service account doesn't exist or we were unable to retrieve its Policy"

            response["service_account_validity"] = {
                str(sa_account_id): sa_validity.get_info()
            }

    return response


def _get_google_project_id_error_status(validity_info):
    has_access = validity_info.get("monitor_has_access")
    user_has_access = validity_info.get("user_has_access")
    valid_parent_org = validity_info.get("valid_parent_org")
    valid_member_types = validity_info.get("valid_member_types")
    members_exist_in_fence = validity_info.get("members_exist_in_fence")
    service_accounts_validity = validity_info.get("service_accounts")

    response = {
        "status": 200,
        "error": None,
        "error_description": "",
        "membership_validity": {
            "valid_member_types": valid_member_types,
            "members_exist_in_fence": members_exist_in_fence,
        },
        "service_account_validity": {},
    }

    if not has_access:
        response["status"] = 404
        response["error"] = ValidationErrors.MONITOR_NOT_FOUND
        response["error_description"] = (
            "Fence's monitoring service account "
            "does not have access to the project and/or the necessary "
            "Google APIs are not enabled."
        )
        return response

    if not user_has_access:
        if not validity_info.google_project_id:
            # if the request doesn't include google_project_id, we want to report that
            # instead of reporting the user doesn't have access to an unnamed project
            response["status"] = 400
            response["error"] = ValidationErrors.GOOGLE_PROJECT_NOT_INCLUDED
            response[
                "error_description"
            ] = "Google Project ID (required) was not included in the request."
        else:
            response["status"] = 403
            response["error"] = ValidationErrors.UNAUTHORIZED_USER
            response["error_description"] = (
                "Current user is not an authorized member on the provided "
                "Google Project."
            )
        return response

    for sa_account_id, sa_validity in service_accounts_validity:
        if sa_account_id != validity_info.new_service_account:
            response["service_account_validity"][sa_account_id] = sa_validity.get_info()
            if not sa_validity:
                response["status"] = 403
                response["error"] = ValidationErrors.UNAUTHORIZED
                response[
                    "error_description"
                ] = "Project has one or more invalid service accounts. "

    if not valid_parent_org:
        response["status"] = 403
        response["error"] = ValidationErrors.UNAUTHORIZED
        response["error_description"] += "Project has parent organization. "

    if not valid_member_types:
        response["status"] = 403
        response["error"] = ValidationErrors.UNAUTHORIZED
        response["error_description"] += "Project has invalid member types. "

    if not members_exist_in_fence:
        response["status"] = 403
        response["error"] = ValidationErrors.UNAUTHORIZED
        response[
            "error_description"
        ] += "Not all Google project members have registered with {}.".format(
            flask.current_app.config.get("APP_NAME", "Gen3")
        )

    return response


def _get_project_access_error_status(validity_info):
    access_validity = validity_info.get("access")

    response = {
        "status": 200,
        "error": None,
        "error_description": "",
        "project_validity": {},
    }

    for project, validity in access_validity:
        if validity.get("exists"):
            if not validity.get("all_users_have_access"):
                response["status"] = 403
                response["error"] = ValidationErrors.UNAUTHORIZED
                message = "Not all users have necessary access to project(s). "
                if message not in response["error_description"]:
                    response["error_description"] += message
        else:
            response["status"] = 404
            response["error"] = ValidationErrors.PROJECT_NOT_FOUND
            response["error_description"] += (
                "A project requested for access "
                "could not be found by the given identifier. "
            )

        response["project_validity"].update({str(project): validity.get_info()})

    return response
