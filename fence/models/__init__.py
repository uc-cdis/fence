"""
Single entry to get to all of fences models (which are logically organized
into separate Python modules).

We import all the models from the sub-modules here but need noqa's so
linters doesn't complain about unused imports
"""
from fence.jwt.token import CLIENT_ALLOWED_SCOPES   # noqa

from fence.models._base import Base  # noqa
from fence.models.access import Application  # noqa
from fence.models.access import Certificate  # noqa
from fence.models.access import ComputeAccess  # noqa
from fence.models.access import StorageAccess  # noqa
from fence.models.access import Project  # noqa
from fence.models.access import UserToBucket  # noqa
from fence.models.access import ProjectToBucket  # noqa
from fence.models.auth import IdentityProvider  # noqa
from fence.models.auth import AuthorizationProvider  # noqa
from fence.models.auth import Client  # noqa
from fence.models.auth import AuthorizationCode  # noqa
from fence.models.cloud_resources import CloudProvider  # noqa
from fence.models.cloud_resources import Bucket  # noqa
from fence.models.cloud_resources import GoogleServiceAccount  # noqa
from fence.models.cloud_resources import GoogleProxyGroup  # noqa
from fence.models.creds import UserRefreshToken  # noqa
from fence.models.creds import S3Credential  # noqa
from fence.models.creds import HMACKeyPair  # noqa
from fence.models.creds import HMACKeyPairArchive  # noqa
from fence.models.users import PrivilegeDict  # noqa
from fence.models.users import AccessPrivilege  # noqa
from fence.models.users import User  # noqa
from fence.models.users import Group  # noqa
from fence.models.users import UserToGroup  # noqa
from fence.models.users import Organization  # noqa
from fence.models.users import Department  # noqa

from fence.models._migrate import migrate  # noqa

IDENTITY_PROVIDERS = ['fence', 'google', 'shibboleth']
