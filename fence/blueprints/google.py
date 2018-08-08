import json
import os
from urllib import unquote

import flask
from flask_restful import Resource

from cirrus import GoogleCloudManager
from cirrus.google_cloud.errors import GoogleAPIError

from fence.auth import current_token, require_auth_header
from fence.restful import RestfulApi
from fence.errors import UserError, NotFound
from fence.resources.google.validity import GoogleProjectValidity
from fence.resources.google.access_utils import (
    is_user_member_of_all_google_projects,
    can_user_manage_service_account,
    get_google_project_from_service_account_email,
    get_service_account_email,
    force_remove_service_account_from_access,
    extend_service_account_access,
    get_current_service_account_project_access,
    patch_user_service_account,
    get_project_ids_from_project_auth_ids,
    add_user_service_account_to_google,
    add_user_service_account_to_db,

)
from fence.models import UserServiceAccount
from flask_sqlalchemy_session import current_session


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

    @require_auth_header({'google_service_account'})
    def post(self):
        """
        Register a new service account
        """
        payload = flask.request.get_json(silent=True) or {}
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

        sa_exists = (
            current_session
            .query(UserServiceAccount)
            .filter_by(email=service_account_email)
            .all()
        )

        if sa_exists:
            error_response['success'] = False
            error_response['errors']['service_account_email'] = {
                'status': 409,
                'error': 'Conflict',
                'error_description': 'Service Account already registered.'
            }
            return error_response, 400

        new_service_account = self._register_new_service_account(
            service_account_email, google_project_id, project_access)

        return new_service_account, 200

    def _register_new_service_account(
            self, service_account_email, google_project_id, project_access):
        """
        Add service account and related entries to database and add
        service account to google bucket access groups

        WARNING: this assumes that the project_access provided are all
        valid Project.auth_ids, currently checked before this is called
        in validity checking

        Args:
            service_account_email(str): email address of
                service account to be registered
            google_project_id(str): unique-id of google project
            project_access(list<(str)>): list of project auth-ids which
                identify which projects the service account should have
                access to

        Return:
            (dict): dictionary representing service account object
        """
        with GoogleCloudManager(google_project_id) as google_project:
            service_account = google_project.get_service_account(
                service_account_email)

        db_service_account = UserServiceAccount(
            google_unique_id=service_account.get('uniqueId'),
            email=service_account.get('email'),
            google_project_id=google_project_id
        )

        current_session.add(db_service_account)
        current_session.commit()

        project_ids = get_project_ids_from_project_auth_ids(
            current_session, project_access)

        add_user_service_account_to_db(
            current_session, project_ids, db_service_account)

        add_user_service_account_to_google(
            current_session, project_ids, db_service_account)

        return {
            'service_account_email': service_account.get('email'),
            'google_project_id': service_account.get('projectId'),
            'project_access': project_access
        }


class GoogleServiceAccount(Resource):

    @require_auth_header({'google_service_account'})
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

    @require_auth_header({'google_service_account'})
    def post(self, id_):
        """
        Dry run for registering a new service account

        Args:
            id_ (str): Must be "_dry_run", otherwise, error
        """
        if id_ != '_dry_run':
            raise UserError('Cannot post with account id_.')

        payload = flask.request.get_json(silent=True) or {}
        service_account_email = payload.get('service_account_email')
        google_project_id = payload.get('google_project_id')
        project_access = payload.get('project_access')

        error_response = _get_service_account_error_status(
            service_account_email, google_project_id, project_access)

        sa_exists = (
            current_session
            .query(UserServiceAccount)
            .filter_by(email=service_account_email)
            .all()
        )

        if sa_exists:
            error_response['success'] = False
            error_response['errors']['service_account_email'] = {
                'status': 409,
                'error': 'Conflict',
                'error_description': 'Service Account already registered.'
            }

        if error_response.get('success') is True:
            status = 200
        else:
            status = 400

        return error_response, status

    @require_auth_header({'google_service_account'})
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

        payload = flask.request.get_json(silent=True) or {}

        service_account_email = get_service_account_email(id_)

        # check if the user requested to update more than project_access
        project_access = (
            payload.pop('project_access', None)
            or get_current_service_account_project_access(service_account_email)
        )

        if payload:
            return (
                'Cannot update provided fields: {}'.format(payload),
                403
            )

        google_project_id = (
            get_google_project_from_service_account_email(service_account_email)
        )
        error_response = _get_service_account_error_status(
            service_account_email, google_project_id, project_access)

        if error_response.get('success') is not True:
            return error_response, 400

        resp, status_code = self._update_service_account_permissions(
            google_project_id, service_account_email, project_access)

        if status_code != 200:
            return resp, status_code

        # extend access to all datasets
        extend_service_account_access(service_account_email)

        return '', 204

    @require_auth_header({'google_service_account'})
    def delete(self, id_):
        """
        Delete a service account

        Args:
            id_ (str): Google service account email to delete
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
        if not monitoring_account_email:
            error = (
                'No monitoring service account. Fence is not currently '
                'configured to support user-registration of service accounts.'
            )
            return {'message': error}, 404

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
            self, google_project_id, service_account_email, project_access):
        """
        Update the given service account's permissions.

        WARNING: NO AUTHORIZATION CHECK DONE HERE. This will blindly update
                 given service account.

        Args:
            google_project_id (str): google project id
            service_account_email (str): Google service account email
            project_access (List(str)): List of Project.auth_ids to authorize
                the service account for

        """
        try:
            patch_user_service_account(
                    google_project_id, service_account_email, project_access)

        except NotFound as exc:
            return (
                'Can not update the service accout {}. Detail {}'.
                format(service_account_email, exc.message), 404
            )
        except GoogleAPIError as exc:
            return (
                'Can not update the service accout {}. Detail {}'.
                format(service_account_email, exc.message), 400
            )
        except Exception:
            return (
                ' Can not delete the service account {}'.
                format(service_account_email), 500
            )

        return (
            'Successfully update service account  {}'
            .format(service_account_email), 200
        )

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
        google_project_id = (
            get_google_project_from_service_account_email(service_account_email)
        )

        try:
            force_remove_service_account_from_access(google_project_id, service_account_email)
        except NotFound as exc:
            return (
                'Can not remove the service accout {}. Detail {}'.
                format(id_, exc.message), 404
            )
        except GoogleAPIError as exc:
            return (
                'Can not remove the service accout {}. Detail {}'.
                format(id_, exc.message), 400
            )
        except Exception:
            return (
                ' Can not delete the service account {}'.
                format(id_), 500
            )

        return 'Successfully delete service account  {}'.format(id_), 200


def _get_service_account_error_status(
        service_account_email, google_project_id, project_access):
    """
    Get a dictionary describing any errors that will occur if attempting
    to give service account specified permissions fails.

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
                        "error": "unauthorized",
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
    if (response['errors']['service_account_email'].get('status') == 200
            and response['errors']['google_project_id'].get('status') == 200
            and response['errors']['project_access'].get('status') == 200):
        response['success'] = True

    return response


def _get_service_account_email_error_status(validity_info):

    service_accounts_validity = validity_info.get('service_accounts')
    if service_accounts_validity:
        return {
            'status': 200,
            'error': None,
            'error_description': ''
        }

    response = {
        'status': 403,
        'error': 'unauthorized',
        'error_description': ''
    }

    for sa_account_id, sa_validity in service_accounts_validity:
        if sa_account_id == validity_info.new_service_account:
            if not sa_validity:
                response['error_description'] = (
                    'Service account requested for registration is invalid.'
                )
                response['service_account_validity'] = {
                    str(sa_account_id): sa_validity._info
                }
            else:
                return {
                    'status': 200,
                    'error': None,
                    'error_description': ''
                }

    return response


def _get_google_project_id_error_status(validity_info):
    has_access = validity_info.get('monitor_has_access')

    if not has_access:
        return {
            'status': 404,
            'error': 'monitor_not_found',
            'error_description': (
                'Fence\'s monitoring service account '
                'does not have access to the project.'
            )
        }

    valid_parent_org = validity_info.get('valid_parent_org')
    valid_membership = validity_info.get('valid_membership')
    service_accounts_validity = validity_info.get('service_accounts')

    response = {
        'status': 200,
        'error': None,
        'error_description': '',
        'service_account_validity': {}
    }

    for sa_account_id, sa_validity in service_accounts_validity:
        if sa_account_id != validity_info.new_service_account:
            response['service_account_validity'][sa_account_id] = (
                sa_validity.get_info()
            )
            if not sa_validity:
                response['status'] = 403
                response['error'] = 'Unauthorized'
                response['error_description'] = 'Project has one or more invalid service accounts.'

    if not valid_parent_org:
        response['status'] = 403
        response['error'] = 'Unauthorized'
        response['error_description'] += 'Project has parent organization. '

    if not valid_membership:
        response['status'] = 403
        response['error'] = 'Unauthorized'
        response['error_description'] += 'Project has invalid membership. '

    return response


def _get_project_access_error_status(validity_info):

    access_validity = validity_info.get('access')

    if access_validity:
        return {
            'status': 200,
            'error': None,
            'error_description': ''
        }

    response = {
        'status': 403,
        'error': 'unauthorized',
        'error_description': 'Not all users have access requested',
        'invalid_access': []
    }

    for project, valid in access_validity:
        if not valid:
            response['invalid_access'].append(project)

    return response


def _get_monitoring_account_email():
    """
    Get the monitoring email from the cirrus configuration. Use the
    main/default application credentials as the monitoring service account.

    This function should ONLY return the service account's email by
    parsing the creds file.
    """
    app_creds_file = (
        flask.current_app.config
        .get('CIRRUS_CFG', {})
        .get('GOOGLE_APPLICATION_CREDENTIALS')
    )

    creds_email = None
    if app_creds_file and os.path.exists(app_creds_file):
        with open(app_creds_file) as app_creds_file:
            creds_email = (
                json.load(app_creds_file)
                .get('client_email')
            )

    return creds_email
