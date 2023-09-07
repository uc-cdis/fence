from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin
from sqlalchemy import Boolean, Column, Integer, String, Text, func
from sqlalchemy.orm import Session, backref, relationship
from sqlalchemy.schema import ForeignKey
from userdatamodel import Base
from userdatamodel.models import User

# This needs to be in a different file
# Otherwise SqlAlchemy would import this multiple times and then complain about metadata conflict
class MigrationClient(Base, OAuth2ClientMixin):

    __tablename__ = "migration_client"

    client_id = Column(String(48), primary_key=True, index=True)
    # this is hashed secret
    client_secret = Column(String(120), unique=True, index=True, nullable=True)

    # human readable name
    name = Column(String(40), nullable=False)

    # human readable description, not required
    description = Column(String(400))

    # required if you need to support client credential
    user_id = Column(Integer, ForeignKey(User.id, ondelete="CASCADE"))
    user = relationship(
        "User",
        backref=backref(
            "migration_clients", cascade="all, delete-orphan", passive_deletes=True
        ),
    )

    # this is for internal microservices to skip user grant
    auto_approve = Column(Boolean, default=False)

    # public or confidential
    is_confidential = Column(Boolean, default=True)

    expires_at = Column(Integer, nullable=False, default=0)

    # Deprecated, keeping these around in case it is needed later
    _default_scopes = Column(Text)
    _scopes = ["compute", "storage", "user"]
    redirect_uri = Column(Text)
    token_endpoint_auth_method = Column(String(48), default="client_secret_basic")
    grant_type = Column(Text, nullable=False, default="")
    response_type = Column(Text, nullable=False, default="")
    scope = Column(Text, nullable=False, default="")

    client_name = Column(String(100))
    client_uri = Column(Text)
    logo_uri = Column(Text)
    contact = Column(Text)
    tos_uri = Column(Text)
    policy_uri = Column(Text)
    jwks_uri = Column(Text)
    jwks_text = Column(Text)
    i18n_metadata = Column(Text)

    software_id = Column(String(36))
    software_version = Column(String(48))
