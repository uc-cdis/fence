import glob
import os
import re
import jwt

from cdislogging import get_logger
from email_validator import validate_email, EmailNotValidError
from gen3authz.client.arborist.errors import ArboristError
from gen3users.validation import validate_user_yaml
from paramiko.proxy import ProxyCommand
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func
from userdatamodel.driver import SQLAlchemyDriver

from fence.config import config
from fence.models import (
    AccessPrivilege,
    AuthorizationProvider,
    Project,
    Tag,
    User,
    query_for_user,
    Client,
)

from fence.resources.storage import StorageManager
from fence.resources.google.access_utils import bulk_update_google_groups
from fence.sync import utils
from fence.sync.passport_sync.ras_sync import RASVisa


class VisaSync(object):
    def __init__(
        self,
        logger=None,
    ):
        self.logger = logger
        # add option for DB and dbsession

    def _pick_type(self, visa):
        """
        Pick type of visa to parse according to the visa provider
        """
        if "ras" in visa.type:
            return RASVisa()

    def _get_single_passport(self, user):
        """
        Retrieve passport stored in fence db
        """
        encoded_visas = [row.ga4gh_visa for row in user.ga4gh_visas_v1]
        return encoded_visas

    def _parse_projects(self, user_projects):
        """
        helper function for parsing projects
        """
        return {key.lower(): value for key, value in user_projects.items()}

    def _parse_user_visas(self, db_session):
        """
        Retrieve all visas from fence db and parse to python dict

        Return:
            Tuple[[dict, dict]]:
                (user_project, user_info) where user_project is a mapping from
                usernames to project permissions and user_info is a mapping
                from usernames to user details, such as email

        Example:

            (
                {
                    username: {
                        'project1': {'read-storage','write-storage'},
                        'project2': {'read-storage'},
                    }
                },
                {
                    username: {
                        'email': 'email@mail.com',
                        'display_name': 'display name',
                        'phone_number': '123-456-789',
                        'tags': {'dbgap_role': 'PI'}
                    }
                },
            )

        """
        user_projects = dict()
        user_info = dict()

        users = db_session.query(User).all()

        for user in users:
            for visa in user.ga4gh_visas_v1:
                visa_type = self._pick_type(visa)
                encoded_visa = visa.ga4gh_visa
                decoded_visa = jwt.decode(encoded_visa, verify=False)
                project, info = visa_type._parse_single_visa(user, decoded_visa)
            user_projects[user.username] = project
            user_info[user.username] = info

        return (user_projects, user_info)

    def sync_to_db_and_storage_backend(self, user_project, user_info, db_session):
        """
        sync user access control to database and storage backend
        """
        google_bulk_mapping = None

    def _single_visa_sync(self, db_session):
        pass

    def _sync(self, db_session):
        """
        Collect passports from db, sync info to backend
        """

        # get all users and info
        user_projects, user_info = self._parse_user_visas(db_session)

        user_projects = self._parse_projects(user_projects)

        # update fence db
        if user_projects:
            self.logger.info("Sync to db and storage backend")

        # is fallback to telemetry? if yes then usersync

        # update arborist db (resources, roles, policies, groups)

        # update arborist db (user access)
