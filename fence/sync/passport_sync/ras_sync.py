import glob
import os
import re
import jwt

from cdislogging import get_logger
from email_validator import validate_email, EmailNotValidError
from flask_sqlalchemy_session import current_session
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
    GA4GHVisaV1,
    Project,
    Tag,
    User,
    query_for_user,
    Client,
)

from fence.resources.storage import StorageManager
from fence.resources.google.access_utils import bulk_update_google_groups
from fence.sync import utils
from .base_sync import DefaultVisa


class RASVisa(DefaultVisa):
    """
    Class representing RAS visas
    """

    def _init__(self, logger, visa_type=None):
        super(RASVisa, self).__init__(
            logger=logger,
            visa_type=visa_type,
        )

        if self.DB is None:
            try:
                from fence.settings import DB
            except ImportError:
                pass


    def _parse_user_visas(self, user, db_session):
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
            project, info = self._parse_single_visa(user)
            user_projects[user.username] = project
            user_info[user.username] = info

        return(user_projects, user_info)     

    def _parse_single_visa(self, user):
        encoded_visas = self._get_single_passport(user)
        decoded_visas = [jwt.decode(visa, verify=False) for visa in encoded_visas]
        project = {}

        for visa in decoded_visas:
            ras_dbgap_permissions = visa.get("ras_dbgap_permissions", [])
            for permission in ras_dbgap_permissions:
                phsid = permission.get("phs_id", "")
                version = permission.get("version", "")
                participant_set = permission.get("participant_set", "")
                consent_group = permission.get("consent_group", "")
                full_phsid = ".".join(filter(None,[phsid, version, participant_set, consent_group]))
                privileges = {"read-storage", "read"}
                project[full_phsid] = privileges

        # Retrieve user information
        info = {}
        info["email"] = user.email or ""
        info["display_name"] = user.display_name or ""
        info["phone_number"] = user.phone_number or ""
        
        return project, info





                
