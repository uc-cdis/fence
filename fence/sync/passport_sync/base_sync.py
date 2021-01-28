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


class DefaultVisa(object):
    """
    Base class for representation of information in a GA4GH passport describing user, project, and ABAC
    information for access control
    """

    def __init__(
        self,
        logger=None,
    ):
        self.logger = logger
        # add option for DB and dbsession 

    def _get_single_passport(self, user):
        """
        Retrieve passport stored in fence db
        TODO: Retrieve visa of specific type.
        """
        encoded_visas = [row.ga4gh_visa for row in user.ga4gh_visas_v1]
        # print(jwt.decode(encoded_visas[0], verify=False))
        return encoded_visas
    
    def _parse_single_visa(self, visa):
        pass

    def _parse_projects(self, user_projects):
        """
        helper function for parsing projects
        """
        return {key.lower(): value for key, value in user_projects.items()}

    def _single_visa_sync(self):
        pass

    def _sync(self):
        # do the sync here for all clients and call parsing depending on _pick_client
        pass
