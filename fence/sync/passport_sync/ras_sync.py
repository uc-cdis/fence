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


    def _parse_single_user_visas(self, user):
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

        # for user in GA4GHVisaV1.user
        DB = os.environ.get("FENCE_DB") or config.get("DB")
        driver = SQLAlchemyDriver(DB)

        username = user.username
        user_projects[username] = {}
        encoded_visas = self._get_single_passport(user)
        decoded_visas = [jwt.decode(visa, verify=False) for visa in encoded_visas]

        # Retrieve phsid information
        user_projects[username] = dict()
        project_list = user_projects[username]
        for decoded_visa in decoded_visas:
            ras_dbgap_permissions = decoded_visa.get("ras_dbgap_permissions", [])
            for permission in ras_dbgap_permissions:
                phsid = permission.get("phs_id", "")
                version = permission.get("version", "")
                participant_set = permission.get("participant_set", "")
                consent_group = permission.get("consent_group", "")
                full_phsid = ".".join(filter(None,[phsid, version, participant_set, consent_group]))
                privileges = {"read-storage", "read"}
                project_list[full_phsid] = privileges
                # TODO: Check/create resources in arborist

        # Retrieve user information
        user_info[username] = dict()
        info = user_info[username]
        info["email"] = user.email or ""
        info["display_name"] = user.display_name or ""
        info["phone_number"] = user.phone_number or ""
        # info["tags"] = {"dbgap_role": user.roles or ""} # Check this out today


        with driver.session as s:
            user = s.query(GA4GHVisaV1).first()
            print(user)


        return(user_projects, user_info)        




                
