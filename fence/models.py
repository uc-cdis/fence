"""
Define sqlalchemy models.
The models here inherit from the `Base` in userdatamodel, so when the fence app
is initialized, the resulting db session includes everything from userdatamodel
and this file.
The `migrate` function in this file is called every init and can be used for
database migrations.
"""

from enum import Enum

from authlib.flask.oauth2.sqla import OAuth2AuthorizationCodeMixin, OAuth2ClientMixin
import bcrypt
import flask
from sqlalchemy import (
    Integer,
    BigInteger,
    String,
    Column,
    Boolean,
    Text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import relationship, backref
from sqlalchemy import func
from sqlalchemy.schema import ForeignKey
from userdatamodel import Base
from userdatamodel.models import (
    AccessPrivilege,
    Application,
    AuthorizationProvider,
    Bucket,
    Certificate,
    CloudProvider,
    ComputeAccess,
    GoogleProxyGroup,
    Group,
    HMACKeyPair,
    HMACKeyPairArchive,
    IdentityProvider,
    Project,
    ProjectToBucket,
    S3Credential,
    StorageAccess,
    Tag,
    User,
    UserToBucket,
    UserToGroup,
)


def query_for_user(session, username):
    return (
        session.query(User)
        .filter(func.lower(User.username) == username.lower())
        .first()
    )


class ClientAuthType(Enum):
    """
    List the possible types of OAuth client authentication, which are
    - None (no authentication).
    - Basic (using basic HTTP authorization header to include the client ID & secret).
    - POST (the client ID & secret are included in the body of a POST request).
    These all have a corresponding string which identifies them to authlib.
    """

    none = "none"
    basic = "client_secret_basic"
    post = "client_secret_post"


class GrantType(Enum):
    """
    Enumerate the allowed grant types for the OAuth2 flow.
    """

    code = "authorization_code"
    refresh = "refresh_token"
    implicit = "implicit"
    client_credentials = "client_credentials"


class Client(Base, OAuth2ClientMixin):

    __tablename__ = "client"

    client_id = Column(String(40), primary_key=True)
    # this is hashed secret
    client_secret = Column(String(60), unique=True, index=True, nullable=True)

    # human readable name
    name = Column(String(40), unique=True, nullable=False)

    # human readable description, not required
    description = Column(String(400))

    # required if you need to support client credential
    user_id = Column(Integer, ForeignKey(User.id, ondelete="CASCADE"))
    user = relationship(
        "User",
        backref=backref("clients", cascade="all, delete-orphan", passive_deletes=True),
    )

    # this is for internal microservices to skip user grant
    auto_approve = Column(Boolean, default=False)

    # public or confidential
    is_confidential = Column(Boolean, default=True)

    # NOTE: DEPRECATED
    # Client now uses `redirect_uri` column, from authlib client model
    _redirect_uris = Column(Text)

    _allowed_scopes = Column(Text, nullable=False, default="")

    _default_scopes = Column(Text)
    _scopes = ["compute", "storage", "user"]

    # note that authlib adds a response_type column which is not used here

    def __init__(self, client_id, **kwargs):
        """
        NOTE that for authlib, the client must have an attribute ``redirect_uri`` which
        is a newline-delimited list of valid redirect URIs.
        """
        if "allowed_scopes" in kwargs:
            allowed_scopes = kwargs.pop("allowed_scopes")
            if isinstance(allowed_scopes, list):
                kwargs["_allowed_scopes"] = " ".join(allowed_scopes)
            else:
                kwargs["_allowed_scopes"] = allowed_scopes
        if "redirect_uris" in kwargs:
            redirect_uris = kwargs.pop("redirect_uris")
            if isinstance(redirect_uris, list):
                kwargs["redirect_uri"] = "\n".join(redirect_uris)
            else:
                kwargs["redirect_uri"] = redirect_uris
        # default grant types to allow for auth code flow and resfreshing
        grant_types = kwargs.pop("grant_types", None) or [
            GrantType.code.value,
            GrantType.refresh.value,
        ]
        if isinstance(grant_types, list):
            kwargs["grant_type"] = "\n".join(grant_types)
        else:
            # assume it's already in correct format
            kwargs["grant_type"] = grant_types

        super(Client, self).__init__(client_id=client_id, **kwargs)

    @property
    def allowed_scopes(self):
        return self._allowed_scopes.split(" ")

    @property
    def client_type(self):
        """
        The client should be considered confidential either if it is actually
        marked confidential, *or* if the confidential setting was left empty.
        Only in the case where ``is_confidential`` is deliberately set to
        ``False`` should the client be considered public.
        """
        if self.is_confidential is False:
            return "public"
        return "confidential"

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes.split()
        return []

    @staticmethod
    def get_by_client_id(client_id):
        with flask.current_app.db.session as session:
            return session.query(Client).filter_by(client_id=client_id).first()

    def check_client_type(self, client_type):
        return (client_type == "confidential" and self.is_confidential) or (
            client_type == "public" and not self.is_confidential
        )

    def check_client_secret(self, client_secret):
        check_hash = bcrypt.hashpw(
            client_secret.encode("utf-8"), self.client_secret.encode("utf-8")
        ).decode("utf-8")
        return check_hash == self.client_secret

    def check_requested_scopes(self, scopes):
        if "openid" not in scopes:
            return False
        return set(self.allowed_scopes).issuperset(scopes)

    def check_token_endpoint_auth_method(self, method):
        """
        Only basic auth is supported. If anything else gets added, change this
        """
        protected_types = [ClientAuthType.basic.value, ClientAuthType.post.value]
        return (self.is_confidential and method in protected_types) or (
            not self.is_confidential and method == ClientAuthType.none.value
        )

    def validate_scopes(self, scopes):
        scopes = scopes[0].split(",")
        return all(scope in self._scopes for scope in scopes)

    def check_response_type(self, response_type):
        allowed_response_types = []
        if "authorization_code" in self.grant_types:
            allowed_response_types.append("code")
        if "implicit" in self.grant_types:
            allowed_response_types.append("id_token")
            allowed_response_types.append("id_token token")
        return response_type in allowed_response_types


class AuthorizationCode(Base, OAuth2AuthorizationCodeMixin):

    __tablename__ = "authorization_code"

    id = Column(Integer, primary_key=True)

    user_id = Column(Integer, ForeignKey("User.id", ondelete="CASCADE"))
    user = relationship(
        "User",
        backref=backref(
            "authorization_codes", cascade="all, delete-orphan", passive_deletes=True
        ),
    )

    nonce = Column(String, nullable=True)

    refresh_token_expires_in = Column(Integer, nullable=True)

    _scope = Column(Text, default="")

    def __init__(self, **kwargs):
        if "scope" in kwargs:
            scope = kwargs.pop("scope")
            if isinstance(scope, list):
                kwargs["_scope"] = " ".join(scope)
            else:
                kwargs["_scope"] = scope
        super(AuthorizationCode, self).__init__(**kwargs)

    @property
    def scope(self):
        return self._scope.split(" ")


class UserRefreshToken(Base):
    __tablename__ = "user_refresh_token"

    jti = Column(String, primary_key=True)
    userid = Column(Integer)
    expires = Column(BigInteger)

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()


class GoogleServiceAccount(Base):
    __tablename__ = "google_service_account"

    id = Column(Integer, primary_key=True)

    # The uniqueId google provides to resources is ONLY unique within
    # the given project, so we shouldn't rely on that for a primary key (in
    # case we're ever juggling mult. projects)
    google_unique_id = Column(String, unique=False, nullable=False)

    client_id = Column(String(40))

    user_id = Column(Integer, ForeignKey(User.id, ondelete="CASCADE"), nullable=False)
    user = relationship(
        "User",
        backref=backref(
            "google_service_accounts",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )

    google_project_id = Column(String, nullable=False)

    email = Column(String, unique=True, nullable=False)

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


class UserGoogleAccount(Base):
    __tablename__ = "user_google_account"

    id = Column(Integer, primary_key=True)

    email = Column(String, unique=True, nullable=False)

    user_id = Column(Integer, ForeignKey(User.id, ondelete="CASCADE"), nullable=False)
    user = relationship(
        "User",
        backref=backref(
            "user_google_accounts", cascade="all, delete-orphan", passive_deletes=True
        ),
    )

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


class UserGoogleAccountToProxyGroup(Base):
    __tablename__ = "user_google_account_to_proxy_group"

    user_google_account_id = Column(
        Integer,
        ForeignKey(UserGoogleAccount.id, ondelete="CASCADE"),
        nullable=False,
        primary_key=True,
    )
    user_google_account = relationship(
        "UserGoogleAccount",
        backref=backref(
            "user_google_account_to_proxy_group",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )

    proxy_group_id = Column(
        String,
        ForeignKey(GoogleProxyGroup.id, ondelete="CASCADE"),
        nullable=False,
        primary_key=True,
    )
    google_proxy_group = relationship(
        "GoogleProxyGroup",
        backref=backref(
            "user_google_account_to_proxy_group",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )

    expires = Column(BigInteger)

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


class GoogleServiceAccountKey(Base):
    __tablename__ = "google_service_account_key"

    id = Column(Integer, primary_key=True)

    key_id = Column(String, nullable=False)

    service_account_id = Column(
        Integer, ForeignKey(GoogleServiceAccount.id, ondelete="CASCADE"), nullable=False
    )
    google_service_account = relationship(
        "GoogleServiceAccount",
        backref=backref(
            "google_service_account_keys",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )

    expires = Column(BigInteger)

    private_key = Column(String)

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


class GoogleBucketAccessGroup(Base):
    __tablename__ = "google_bucket_access_group"
    id = Column(Integer, primary_key=True)

    bucket_id = Column(
        Integer, ForeignKey(Bucket.id, ondelete="CASCADE"), nullable=False
    )
    bucket = relationship(
        "Bucket",
        backref=backref(
            "google_bucket_access_groups",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )

    email = Column(String, nullable=False)

    # specify what kind of storage access this group has e.g. ['read-storage']
    privileges = Column(ARRAY(String))

    def delete(self):
        with flask.current_app.db.session as session:
            session.delete(self)
            session.commit()
            return self


class GoogleProxyGroupToGoogleBucketAccessGroup(Base):
    __tablename__ = "google_proxy_group_to_google_bucket_access_group"
    id = Column(Integer, primary_key=True)

    proxy_group_id = Column(
        String, ForeignKey(GoogleProxyGroup.id, ondelete="CASCADE"), nullable=False
    )
    proxy_group = relationship(
        "GoogleProxyGroup",
        backref=backref(
            "google_proxy_group_to_google_bucket_access_group",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )

    access_group_id = Column(
        Integer,
        ForeignKey(GoogleBucketAccessGroup.id, ondelete="CASCADE"),
        nullable=False,
    )
    access_group = relationship(
        "GoogleBucketAccessGroup",
        backref=backref(
            "google_proxy_group_to_google_bucket_access_group",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )


class UserServiceAccount(Base):
    __tablename__ = "user_service_account"
    id = Column(Integer, primary_key=True)

    # The uniqueId google provides to resources is ONLY unique within
    # the given project, so we shouldn't rely on that for a primary key (in
    # case we're ever juggling mult. projects)
    google_unique_id = Column(String, nullable=False)

    email = Column(String, nullable=False)

    google_project_id = Column(String, nullable=False)


class ServiceAccountAccessPrivilege(Base):
    __tablename__ = "service_account_access_privilege"

    id = Column(Integer, primary_key=True)

    project_id = Column(
        Integer, ForeignKey(Project.id, ondelete="CASCADE"), nullable=False
    )
    project = relationship(
        "Project",
        backref=backref(
            "sa_access_privileges", cascade="all, delete-orphan", passive_deletes=True
        ),
    )

    service_account_id = Column(
        Integer, ForeignKey(UserServiceAccount.id, ondelete="CASCADE"), nullable=False
    )
    service_account = relationship(
        "UserServiceAccount",
        backref=backref(
            "access_privileges", cascade="all, delete-orphan", passive_deletes=True
        ),
    )


class ServiceAccountToGoogleBucketAccessGroup(Base):
    __tablename__ = "service_account_to_google_bucket_access_group"
    id = Column(Integer, primary_key=True)

    service_account_id = Column(
        Integer, ForeignKey(UserServiceAccount.id, ondelete="CASCADE"), nullable=False
    )
    service_account = relationship(
        "UserServiceAccount",
        backref=backref(
            "to_access_groups", cascade="all, delete-orphan", passive_deletes=True
        ),
    )

    expires = Column(BigInteger)

    access_group_id = Column(
        Integer,
        ForeignKey(GoogleBucketAccessGroup.id, ondelete="CASCADE"),
        nullable=False,
    )

    access_group = relationship(
        "GoogleBucketAccessGroup",
        backref=backref(
            "to_access_groups", cascade="all, delete-orphan", passive_deletes=True
        ),
    )


class AssumeRoleCacheAWS(Base):
    __tablename__ = "assume_role_cache"

    arn = Column(String(), primary_key=True)
    expires_at = Column(Integer())
    aws_access_key_id = Column(String())
    aws_secret_access_key = Column(String())
    aws_session_token = Column(String())


class AssumeRoleCacheGCP(Base):
    __tablename__ = "gcp_assume_role_cache"

    gcp_proxy_group_id = Column(String(), primary_key=True)
    expires_at = Column(Integer())
    gcp_private_key = Column(String())
    gcp_key_db_entry = Column(String())


class GA4GHVisaV1(Base):

    __tablename__ = "ga4gh_visa_v1"

    # As Fence will consume visas from many visa issuers, will not use jti as pkey
    id = Column(BigInteger, primary_key=True)

    user_id = Column(Integer, ForeignKey(User.id, ondelete="CASCADE"), nullable=False)
    user = relationship(
        "User",
        backref=backref(
            "ga4gh_visas_v1", cascade="all, delete-orphan", passive_deletes=True
        ),
    )
    ga4gh_visa = Column(Text, nullable=False)  # In encoded form
    source = Column(String, nullable=False)
    type = Column(String, nullable=False)
    asserted = Column(BigInteger, nullable=False)
    expires = Column(BigInteger, nullable=False)


class UpstreamRefreshToken(Base):
    # General table to store any refresh_token sent from any oidc client

    __tablename__ = "upstream_refresh_token"

    id = Column(BigInteger, primary_key=True)

    user_id = Column(Integer, ForeignKey(User.id, ondelete="CASCADE"), nullable=False)
    user = relationship(
        "User",
        backref=backref(
            "upstream_refresh_tokens",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )
    refresh_token = Column(Text, nullable=False)
    expires = Column(BigInteger, nullable=False)
