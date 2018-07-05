from urllib import unquote, quote

import flask
from flask_restful import Resource

from fence.auth import current_token
from fence.restful import RestfulApi
from fence.auth import require_auth_header
from fence.errors import UserError


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
        GoogleServiceAccount, '/service_accounts/<id>',
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

        if not error_response.get('success') is True:
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
    def get(self, id):
        """
        Get service account(s)

        Args:
            id (str): either "monitor" or a comma-delimited list of Google
                      Project IDs to get list of service accounts for.

                      Specifying "monitor" will return the service account
                      email used for monitoring purposes.
        """
        if id == 'monitor':
            return self._get_monitoring_service_account_response()

        # if not monitor, we should assume google project ids and parse
        google_project_ids = [
            project_id.strip()
            for project_id in
            unquote(id).split(',')
        ]

        # check if user has permission to get service accounts
        # for these projects
        user_id = current_token['sub']
        authorized = _is_user_member_of_all_projects(
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
    def post(self, id):
        """
        Dry run for registering a new service account

        Args:
            id (str): Must be "_dry_run", otherwise, error
        """
        if id == '_dry_run':
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
        else:
            raise UserError('Cannot post with account id.')

    @require_auth_header({'user'})
    def patch(self, id):
        """
        Update a service account

        Args:
            id (str): Google service account identifier to update
        """
        user_id = current_token['sub']
        # check if user has permission to update the service account
        authorized = _can_user_manage_service_account(user_id, id)

        if not authorized:
            return (
                'User "{}" does not have permission to update the provided '
                'service account "{}".'.format(user_id, id),
                403
            )

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

        service_account_email = _get_service_account_email(id)
        google_project_id = (
            _get_google_project_from_service_account_email(service_account_email)
        )
        error_response = _get_service_account_error_status(
            service_account_email, google_project_id, project_access)

        if not error_response.get('success') is True:
            return error_response, 400

        self._update_service_account_permissions(
            service_account_email, project_access)

        return '', 200

    @require_auth_header({'user'})
    def delete(self, id):
        """
        Delete a service account

        Args:
            id (str): Google service account identifier to delete
        """
        user_id = current_token['sub']
        # check if user has permission to delete the service account
        authorized = _can_user_manage_service_account(user_id, id)

        if not authorized:
            return (
                'User "{}" does not have permission to delete the provided '
                'service account "{}".'.format(user_id, id),
                403
            )

        return self._delete(id)

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


def _is_user_member_of_all_projects(user_id, google_project_ids):
    """
    Return whether or not the given user is a member of ALL of the provided
    Google project IDs.

    This will verify that either the user's email or their linked Google
    account email exists as a member in the projects.

    Args:
        user_id (int): User identifier
        google_project_ids (List(str)): List of unique google project ids

    Returns:
        bool: whether or not the given user is a member of ALL of the provided
              Google project IDs
    """
    # TODO actually check
    return False


def _can_user_manage_service_account(user_id, account_id):
    """
    Return whether or not the user has permission to update and/or delete the
    given service account.

    Args:
        user_id (int): user's identifier
        account_id (str): service account identifier

    Returns:
        bool: Whether or not the user has permission
    """
    service_account_email = _get_service_account_email(account_id)
    service_account_project = (
        _get_google_project_from_service_account_email(service_account_email)
    )

    # check if user is on project
    return _is_user_member_of_all_projects(user_id, [service_account_project])


def _get_service_account_error_status(
        service_account_email, google_project_id, project_access):
    """
    Get a dictionary describing any errors that will occur if attempting
    to give service account specified permissions.

    Args:
        service_account_email (str): Google service account email
        google_project_id (str): Google project identifier
        project_access (List(str)): List of Project.auth_ids to authorize
            the service account for

    Returns:
        dict: error information

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

    response['errors']['service_account_email'] = (
        _get_service_account_email_error_status(service_account_email)
    )

    response['errors']['google_project_id'] = (
        _get_google_project_id_error_status(google_project_id)
    )

    response['errors']['project_access'] = (
        _get_project_access_error_status(service_account_email, project_access)
    )

    # all statuses must be 200 to be successful
    project_statuses = [
        error_details.get('status')
        for project_name, error_details
        in response['errors']['project_access'].iteritems()
    ]
    if (response['errors']['service_account_email'].get('status') == 200
            and response['errors']['google_project_id'].get('status') == 200
            and set(project_statuses) == set([200])):
        response['success'] = True

    return response


def _get_service_account_email_error_status(service_account_email):
    # TODO actually validate
    response = {
        'status': 400,
        'error': None,
        'error_description': ''
    }
    return response


def _get_google_project_id_error_status(google_project_id):
    # TODO actually validate
    response = {
        'status': 400,
        'error': None,
        'error_description': ''
    }
    return response


def _get_project_access_error_status(service_account_email, project_access):
    response = {}
    # TODO check if permissions are valid
    for project in set(project_access):
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
    # TODO get monitoring service account email. this should probably be a
    # configuration value
    return None


# TODO this should be in cirrus rather than fence...
def _get_service_account_email(account_id):
    # first check if the account_id is an email, if not, hit google's api to
    # get service account information and parse email
    return None


# TODO this should be in cirrus rather than fence...
def _get_google_project_from_service_account_email(account_id):
    # parse email to get project id
    return None
