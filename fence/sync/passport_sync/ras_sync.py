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

    def _init__(self, logger):
        super(RASVisa, self).__init__(
            logger=logger,
        )

        if self.DB is None:
            try:
                from fence.settings import DB
            except ImportError:
                pass

    def _parse_single_visa(self, user, visa):
        ras_dbgap_permissions = visa.get("ras_dbgap_permissions", [])
        project = {}
        for permission in ras_dbgap_permissions:
            phsid = permission.get("phs_id", "")
            version = permission.get("version", "")
            participant_set = permission.get("participant_set", "")
            consent_group = permission.get("consent_group", "")
            full_phsid = ".".join(
                filter(None, [phsid, version, participant_set, consent_group])
            )
            privileges = {"read-storage", "read"}
            project[full_phsid] = privileges

        info = {}
        info["email"] = user.email or ""
        info["display_name"] = user.display_name or ""
        info["phone_number"] = user.phone_number or ""

        return project, info
