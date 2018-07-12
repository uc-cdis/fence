from urllib import unquote

import flask
from flask_restful import Resource

from fence.auth import current_token, require_auth_header
from fence.restful import RestfulApi
from fence.errors import UserError
from fence.resources.google.validity import GoogleProjectValidity
from fence.resources.google.access_utils import (
    is_user_member_of_all_google_projects,
    can_user_manage_service_account,
    get_google_project_from_service_account_email,
    get_service_account_email
)


def make_google_blueprint():
    """
    Return:
        flask.Blueprint: the blueprint used for ``/google`` endpoints
    """
    blueprint = flask.Blueprint('google', __name__)
    blueprint_api = RestfulApi(blueprint)

    blueprint_api.add_resource(
        GoogleServiceAccountRoot, '/service_accounts', strict_slashes=False
    )

    blueprint_api.add_resource(
        GoogleServiceAccount, '/service_accounts/<id_>',
        strict_slashes=False
    )

    return blueprint


class GoogleServiceAccountRoot(Resource):

    @require_auth_header({'user'})  # TODO change scope to something else?
    def post(self):
        """
        Register a new service account
        """
        payload = flask.request.get_json() or {}
        service_account_email = payload.get('service_account_email')
        google_project_id = payload.get('google_project_id')
        project_access = payload.get('project_access')

        return self._post_new_service_account(
            service_account_email=service_account_email,
            google_project_id=google_project_id,
            project_access=project_access,
        )

    def _post_new_service_account(
            self, service_account_email, google_project_id, project_access):
        """
        Return response tuple for registering a new service account

        Args:
            service_account_email (str): Google service account email
            google_project_id (str): Google project identifier
            project_access (List(str)): List of Project.auth_ids to authorize
                the service account for

        Returns:
            tuple(dict, int): (response_data, http_status_code)
        """
        error_response = _get_service_account_error_status(
            service_account_email, google_project_id, project_access)

        if error_response.get('success') is not True:
            return error_response, 400

        new_service_account = self._register_new_service_account(
            service_account_email, google_project_id, project_access)

        return new_service_account, 200

    def _register_new_service_account(
            self, service_account_email, google_project_id, project_access):
        # TODO
        return {}


class GoogleServiceAccount(Resource):

    @require_auth_header({'user'})
    def get(self, id_):
        """
        Get registered service account(s) and their access expiration.

        Args:
            id_ (str): either "monitor" or a comma-delimited list of Google
                      Project IDs to get list of service accounts for.

                      Specifying "monitor" will return the service account
                      email used for monitoring purposes.
        """
        if id_ == 'monitor':
            return self._get_monitoring_service_account_response()

        # if not monitor, we should assume google project ids and parse
        google_project_ids = [
            project_id.strip()
            for project_id in
            unquote(id_).split(',')
        ]

        # check if user has permission to get service accounts
        # for these projects
        user_id = current_token['sub']
        authorized = is_user_member_of_all_google_projects(
            user_id, google_project_ids)

        if not authorized:
            return (
                'User is not a member on all the provided Google project IDs.',
                403
            )

        service_accounts = self._get_project_service_accounts(
            google_project_ids=google_project_ids
        )

        response = {
            'service_accounts': service_accounts
        }

        return response, 200

    @require_auth_header({'user'})
    def post(self, id_):
        """
        Dry run for registering a new service account

        Args:
            id_ (str): Must be "_dry_run", otherwise, error
        """
        if id_ != '_dry_run':
            raise UserError('Cannot post with account id_.')

        payload = flask.request.get_json() or {}
        service_account_email = payload.get('service_account_email')
        google_project_id = payload.get('google_project_id')
        project_access = payload.get('project_access')

        error_response = _get_service_account_error_status(
            service_account_email, google_project_id, project_access)

        if error_response.get('success') is True:
            status = 200
        else:
            status = 400

        return error_response, status

    @require_auth_header({'user'})
    def patch(self, id_):
        """
        Update a service account

        Args:
            id_ (str): Google service account identifier to update
        """
        user_id = current_token['sub']
        # check if user has permission to update the service account
        authorized = can_user_manage_service_account(user_id, id_)

        if not authorized:
            msg = (
                'User "{}" does not have permission to update the provided '
                'service account "{}".'.format(user_id, id_)
            )
            return msg, 403

        payload = flask.request.get_json() or {}
        project_access = payload.get('project_access')

        # check if the user requested to update more than project_access
        if 'project_access' in payload:
            del payload['project_access']
        if payload:
            return (
                'Cannot update provided fields: {}'.format(payload),
                403
            )

        service_account_email = get_service_account_email(id_)
        google_project_id = (
            get_google_project_from_service_account_email(service_account_email)
        )
        error_response = _get_service_account_error_status(
            service_account_email, google_project_id, project_access)

        if error_response.get('success') is not True:
            return error_response, 400

        self._update_service_account_permissions(
            service_account_email, project_access)

        return '', 204

    @require_auth_header({'user'})
    def delete(self, id_):
        """
        Delete a service account

        Args:
            id_ (str): Google service account identifier to delete
        """
        user_id = current_token['sub']
        # check if user has permission to delete the service account
        authorized = can_user_manage_service_account(user_id, id_)

        if not authorized:
            return (
                'User "{}" does not have permission to delete the provided '
                'service account "{}".'.format(user_id, id_),
                403
            )

        return self._delete(id_)

    def _get_monitoring_service_account_response(self):
        """
        Return a response that includes our app's service account used
        for monitoring user's Google projects.

        Returns:
            tuple(dict, int): (response_data, http_status_code)
        """
        monitoring_account_email = _get_monitoring_account_email()
        response = {
            'service_account_email': monitoring_account_email
        }
        return response, 200

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
        raise NotImplementedError('Functionality not yet available...')

    def _update_service_account_permissions(
            self, service_account_email, project_access):
        """
        Update the given service account's permissions.

        WARNING: NO AUTHORIZATION CHECK DONE HERE. This will blindly update
                 given service account.

        Args:
            service_account_email (str): Google service account email
            project_access (List(str)): List of Project.auth_ids to authorize
                the service account for

        Raises:
            NotImplementedError: Description
        """
        raise NotImplementedError('Functionality not yet available...')

    def _delete(self, account_id):
        """
        Delete the given service account from our db and Google if it
        exists.

        WARNING: NO AUTHORIZATION CHECK DONE HERE. This will blindly delete
                 given service account.

        Args:
            account_id (str): Google service account identifier
        """
        raise NotImplementedError('Functionality not yet available...')


def _get_service_account_error_status(
        service_account_email, google_project_id, project_access):
    """
    Get a dictionary describing any errors that will occur if attempting
    to give service account specified permissions fails.

    Response will ONLY contain { "success": True } if no errors.

    Args:
        service_account_email (str): Google service account email
        google_project_id (str): Google project identifier
        project_access (List(str)): List of Project.auth_ids to authorize
            the service account for

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
                        "error": "Unauthorized",
                        "error_description": "Not all users have access requested"
                    }
                }
            }
        }
    """
    response = {
        'success': False,
        'errors': {
            'service_account_email': None,
            'google_project_id': None,
            'project_access': None,
        }
    }

    project_validity = (
        GoogleProjectValidity(
            google_project_id=google_project_id,
            new_service_account=service_account_email,
            new_service_account_access=project_access
        )
    )
    project_validity.check_validity(early_return=False)

    response['errors']['service_account_email'] = (
        _get_service_account_email_error_status(
            project_validity)
    )

    response['errors']['google_project_id'] = (
        _get_google_project_id_error_status(
            project_validity)
    )

    response['errors']['project_access'] = (
        _get_project_access_error_status(
            project_validity)
    )

    # all statuses must be 200 to be successful
    project_statuses = [
        error_details.get('status')
        for project_name, error_details
        in response['errors']['project_access'].iteritems()
    ]
    if (response['errors']['service_account_email'].get('status') == 200
            and response['errors']['google_project_id'].get('status') == 200
            and set(project_statuses) == {200}):
        response['success'] = True
        del response['errors']

    return response


def _get_service_account_email_error_status(validity_info):
    # TODO actually validate
    validity_info = validity_info.get('service_accounts')
    response = {
        'status': 400,
        'error': None,
        'error_description': ''
    }
    return response


def _get_google_project_id_error_status(validity_info):
    # TODO actually validate
    # valid_parent_org = validity_info.get('valid_parent_org')
    # valid_membership = validity_info.get('valid_membership')
    response = {
        'status': 400,
        'error': None,
        'error_description': ''
    }
    return response


def _get_project_access_error_status(validity_info):
    validity_info = validity_info.get('access')
    response = {}
    # TODO check if permissions are valid
    for project, info in validity_info:
        # TODO check if all users on project have permissions, update status
        #      and error info if there's an issue
        response.update({
            str(project): {
                'status': 400,
                'error': None,
                'error_description': ''
            }
        })

    return response


def _get_monitoring_account_email():
    # TODO get monitoring service account from CIRRUS_CFG. Will be the service
    #      accont email used for the fence service
    raise NotImplementedError('Functionality not yet available...')
