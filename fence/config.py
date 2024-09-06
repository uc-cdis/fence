import os
from functools import wraps

import bcrypt
import flask
import requests
from werkzeug.datastructures import ImmutableMultiDict
from yaml import safe_load as yaml_load
import urllib.parse

import gen3cirrus
from gen3config import Config

from cdislogging import get_logger
from fence.settings import CONFIG_SEARCH_FOLDERS
from fence.utils import log_backoff_retry, log_backoff_giveup, exception_do_not_retry, generate_client_credentials, \
    logger
from fence.models import Client, User, query_for_user
from fence.errors import NotFound
from userdatamodel import Base
from sqlalchemy import (
    Integer,
    String,
    Column,
    text,
    event,
    ForeignKey)
from sqlalchemy.orm import relationship, backref
from sqlalchemy.dialects.postgresql import JSONB
from userdatamodel.models import (
    IdentityProvider,
    User)

logger = get_logger(__name__)

DEFAULT_CFG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config-default.yaml"
)


class FenceConfig(Config):
    def post_process(self):
        # backwards compatibility if no new YAML cfg provided
        # these cfg use to be in settings.py so we need to make sure they gets defaulted
        default_config = yaml_load(
            open(
                os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), "config-default.yaml"
                )
            )
        )

        defaults = [
            "APPLICATION_ROOT",
            "AUTHLIB_INSECURE_TRANSPORT",
            "SESSION_COOKIE_SECURE",
            "ACCESS_TOKEN_COOKIE_NAME",
            "SESSION_COOKIE_NAME",
            "OAUTH2_TOKEN_EXPIRES_IN",
            "ACCESS_TOKEN_EXPIRES_IN",
            "REFRESH_TOKEN_EXPIRES_IN",
            "SESSION_TIMEOUT",
            "SESSION_LIFETIME",
            "RENEW_ACCESS_TOKEN_BEFORE_EXPIRATION",
            "GOOGLE_SERVICE_ACCOUNT_KEY_FOR_URL_SIGNING_EXPIRES_IN",
            "GOOGLE_USER_SERVICE_ACCOUNT_ACCESS_EXPIRES_IN",
            "GOOGLE_ACCOUNT_ACCESS_EXPIRES_IN",
            "ACCESS_TOKEN_EXPIRES_IN",
            "dbGaP",
            "CIRRUS_CFG",
            "WHITE_LISTED_GOOGLE_PARENT_ORGS",
            "CLIENT_CREDENTIALS_ON_DOWNLOAD_ENABLED",
            "DATA_UPLOAD_BUCKET",
        ]
        for default in defaults:
            self.force_default_if_none(default, default_cfg=default_config)

        # allow setting DB connection string via env var
        if os.environ.get("DB"):
            logger.info(
                "Found environment variable 'DB': overriding 'DB' field from config file"
            )
            self["DB"] = os.environ["DB"]
        else:
            logger.info(
                "Environment variable 'DB' empty or not set: using 'DB' field from config file"
            )

        # allow setting INDEXD_PASSWORD via env var
        if os.environ.get("INDEXD_PASSWORD"):
            logger.info(
                "Found environment variable 'INDEXD_PASSWORD': overriding 'INDEXD_PASSWORD' field from config file"
            )
            self["INDEXD_PASSWORD"] = os.environ["INDEXD_PASSWORD"]
        else:
            logger.debug(
                "Environment variable 'INDEXD_PASSWORD' empty or not set: using 'INDEXD_PASSWORD' field from config file"
            )

        if "ROOT_URL" not in self._configs and "BASE_URL" in self._configs:
            url = urllib.parse.urlparse(self._configs["BASE_URL"])
            self._configs["ROOT_URL"] = "{}://{}".format(url.scheme, url.netloc)

        # allow authlib traffic on http for development if enabled. By default
        # it requires https.
        #
        # NOTE: use when fence will be deployed in such a way that fence will
        #       only receive traffic from internal clients, and can safely use HTTP
        if (
                self._configs.get("AUTHLIB_INSECURE_TRANSPORT")
                and "AUTHLIB_INSECURE_TRANSPORT" not in os.environ
        ):
            os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"

        # if we're mocking storage, ignore the storage backends provided
        # since they'll cause errors if misconfigured
        if self._configs.get("MOCK_STORAGE", False):
            self._configs["STORAGE_CREDENTIALS"] = {}

        gen3cirrus.config.config.update(**self._configs.get("CIRRUS_CFG", {}))

        # if we have a default google project for billing requester pays, we should
        # NOT allow end-users to have permission to create Temporary Google Service
        # Account credentials, as they could use the default project to bill non-Fence
        # aware Google Buckets
        #
        # NOTE: This does NOT restrict clients from generating temporary service account
        #       credentials under the assumption that the clients are trusted 1) not
        #       to share the credentials directly with end-users and 2) will not mis-use
        #       billing rights (in other words, only use it when interacting with buckets
        #       Fence is aware of)
        if self._configs.get("BILLING_PROJECT_FOR_SA_CREDS") or self._configs.get(
                "BILLING_PROJECT_FOR_SIGNED_URLS"
        ):
            if (
                    "USER_ALLOWED_SCOPES" in self._configs
                    and "google_credentials" in self._configs["USER_ALLOWED_SCOPES"]
            ):
                logger.warning(
                    "Configuration does not restrict end-user access to billing. Correcting. "
                    "BILLING_PROJECT_FOR_SA_CREDS or BILLING_PROJECT_FOR_SIGNED_URLS is set to a non-None value. "
                    "USER_ALLOWED_SCOPES includes `google_credentials`. Removing "
                    "`google_credentials` from USER_ALLOWED_SCOPES as this could allow "
                    "end-users to indescriminently bill our default project. Clients are inheritently "
                    "trusted, so we do not restrict this scope for clients."
                )
                self._configs["USER_ALLOWED_SCOPES"].remove("google_credentials")

            if (
                    "SESSION_ALLOWED_SCOPES" in self._configs
                    and "google_credentials" in self._configs["SESSION_ALLOWED_SCOPES"]
            ):
                logger.warning(
                    "Configuration does not restrict end-user access to billing. Correcting. "
                    "BILLING_PROJECT_FOR_SA_CREDS or BILLING_PROJECT_FOR_SIGNED_URLS is set to a non-None value. "
                    "SESSION_ALLOWED_SCOPES includes `google_credentials`. Removing "
                    "`google_credentials` from USER_ALLOWED_SCOPES as this could allow "
                    "end-users to indiscriminately bill our default project. Clients are inherently "
                    "trusted, so we do not restrict this scope for clients."
                )
                self._configs["SESSION_ALLOWED_SCOPES"].remove("google_credentials")

        if (
                not self._configs["ENABLE_VISA_UPDATE_CRON"]
                and self._configs["GLOBAL_PARSE_VISAS_ON_LOGIN"] is not False
        ):
            raise Exception(
                "Visa parsing on login is enabled but `ENABLE_VISA_UPDATE_CRON` is disabled!"
            )

        for idp_id, idp in self._configs.get("OPENID_CONNECT", {}).items():
            mfa_info = idp.get("multifactor_auth_claim_info")
            if mfa_info and mfa_info["claim"] not in ["amr", "acr"]:
                logger.warning(
                    f"IdP '{idp_id}' is using multifactor_auth_claim_info '{mfa_info['claim']}', which is neither AMR or ACR. Unable to determine if a user used MFA. Fence will continue and assume they have not used MFA."
                )

        self._validate_parent_child_studies(self._configs["dbGaP"])

    @staticmethod
    def _validate_parent_child_studies(dbgap_configs):
        if isinstance(dbgap_configs, list):
            configs = dbgap_configs
        else:
            configs = [dbgap_configs]

        all_parent_studies = set()
        for dbgap_config in configs:
            parent_studies = dbgap_config.get(
                "parent_to_child_studies_mapping", {}
            ).keys()
            conflicts = parent_studies & all_parent_studies
            if len(conflicts) > 0:
                raise Exception(
                    f"{conflicts} are duplicate parent study ids found in parent_to_child_studies_mapping for "
                    f"multiple dbGaP configurations."
                )
            all_parent_studies.update(parent_studies)


config = FenceConfig(DEFAULT_CFG_PATH)
config.load(config_path=os.environ.get("FENCE_CONFIG_PATH"), search_folders=CONFIG_SEARCH_FOLDERS,)
DEFAULT_BACKOFF_SETTINGS = {
    "on_backoff": log_backoff_retry,
    "on_giveup": log_backoff_giveup,
    # todo: config does not have this key but it probably should. why broken?
    "max_tries": config.get("DEFAULT_BACKOFF_SETTINGS_MAX_TRIES", 3),
    "giveup": exception_do_not_retry,
}


def send_email(from_email, to_emails, subject, text, smtp_domain):
    """
    Send email to group of emails using mail gun api.

    https://app.mailgun.com/

    Args:
        from_email(str): from email
        to_emails(list): list of emails to receive the messages
        text(str): the text message
        smtp_domain(dict): smtp domain server

            {
                "smtp_hostname": "smtp.mailgun.org",
                "default_login": "postmaster@mailgun.planx-pla.net",
                "api_url": "https://api.mailgun.net/v3/mailgun.planx-pla.net",
                "smtp_password": "password", # pragma: allowlist secret
                "api_key": "api key" # pragma: allowlist secret
            }

    Returns:
        Http response

    Exceptions:
        KeyError

    """
    if smtp_domain not in config["GUN_MAIL"] or not config["GUN_MAIL"].get(
            smtp_domain
    ).get("smtp_password"):
        raise NotFound(
            "SMTP Domain '{}' does not exist in configuration for GUN_MAIL or "
            "smtp_password was not provided. "
            "Cannot send email.".format(smtp_domain)
        )

    api_key = config["GUN_MAIL"][smtp_domain].get("api_key", "")
    email_url = config["GUN_MAIL"][smtp_domain].get("api_url", "") + "/messages"

    return requests.post(
        email_url,
        auth=("api", api_key),
        data={"from": from_email, "to": to_emails, "subject": subject, "text": text},
    )


def create_client(
        DB,
        username=None,
        urls=[],
        name="",
        description="",
        auto_approve=False,
        is_admin=False,
        grant_types=None,
        confidential=True,
        arborist=None,
        policies=None,
        allowed_scopes=None,
        expires_in=None,
):
    client_id, client_secret, hashed_secret = generate_client_credentials(confidential)
    if arborist is not None:
        arborist.create_client(client_id, policies)
    driver = get_SQLAlchemyDriver(DB)
    auth_method = "client_secret_basic" if confidential else "none"

    allowed_scopes = allowed_scopes or config["CLIENT_ALLOWED_SCOPES"]
    if not set(allowed_scopes).issubset(set(config["CLIENT_ALLOWED_SCOPES"])):
        raise ValueError(
            "Each allowed scope must be one of: {}".format(
                config["CLIENT_ALLOWED_SCOPES"]
            )
        )

    if "openid" not in allowed_scopes:
        allowed_scopes.append("openid")
        logger.warning('Adding required "openid" scope to list of allowed scopes.')

    with driver.session as s:
        user = None
        if username:
            user = query_for_user(session=s, username=username)
            if not user:
                user = User(username=username, is_admin=is_admin)
                s.add(user)

        if s.query(Client).filter(Client.name == name).first():
            if arborist is not None:
                arborist.delete_client(client_id)
            raise Exception("client {} already exists".format(name))

        client = Client(
            client_id=client_id,
            client_secret=hashed_secret,
            user=user,
            redirect_uris=urls,
            allowed_scopes=" ".join(allowed_scopes),
            description=description,
            name=name,
            auto_approve=auto_approve,
            grant_types=grant_types,
            is_confidential=confidential,
            token_endpoint_auth_method=auth_method,
            expires_in=expires_in,
        )
        s.add(client)
        s.commit()

    return client_id, client_secret


def hash_secret(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        has_secret = "client_secret" in flask.request.form
        has_client_id = "client_id" in flask.request.form
        if flask.request.form and has_secret and has_client_id:
            form = flask.request.form.to_dict()
            with flask.current_app.db.session as session:
                client = (
                    session.query(Client)
                    .filter(Client.client_id == form["client_id"])
                    .first()
                )
                if client:
                    form["client_secret"] = bcrypt.hashpw(
                        form["client_secret"].encode("utf-8"),
                        client.client_secret.encode("utf-8"),
                    ).decode("utf-8")
                flask.request.form = ImmutableMultiDict(form)

        return f(*args, **kwargs)

    return wrapper


def get_SQLAlchemyDriver(db_conn_url):
    from userdatamodel.driver import SQLAlchemyDriver

    # override userdatamodel's `setup_db` function which creates tables
    # and runs database migrations, because Alembic handles that now.
    # TODO move userdatamodel code to Fence and remove dependencies to it
    SQLAlchemyDriver.setup_db = lambda _: None
    return SQLAlchemyDriver(db_conn_url)


def get_issuer_to_idp():
    possibly_matching_idps = [IdentityProvider.ras]
    issuer_to_idp = {}

    oidc = config.get("OPENID_CONNECT", {})
    for idp in possibly_matching_idps:
        discovery_url = oidc.get(idp, {}).get("discovery_url")
        if discovery_url:
            for allowed_issuer in config["GA4GH_VISA_ISSUER_ALLOWLIST"]:
                if discovery_url.startswith(allowed_issuer):
                    issuer_to_idp[allowed_issuer] = idp
                    break

    return issuer_to_idp


class IssSubPairToUser(Base):
    # issuer & sub pair mapping to Gen3 User sub

    __tablename__ = "iss_sub_pair_to_user"

    iss = Column(String(), primary_key=True)
    sub = Column(String(), primary_key=True)

    fk_to_User = Column(
        Integer, ForeignKey(User.id, ondelete="CASCADE"), nullable=False
    )  #  foreign key for User table
    user = relationship(
        "User",
        backref=backref(
            "iss_sub_pairs",
            cascade="all, delete-orphan",
            passive_deletes=True,
        ),
    )

    # dump whatever idp provides in here
    extra_info = Column(JSONB(), server_default=text("'{}'"))


@event.listens_for(IssSubPairToUser.__table__, "after_create")
def populate_iss_sub_pair_to_user_table(target, connection, **kw):
    """
    Populate iss_sub_pair_to_user table using User table's id_from_idp
    column.
    """
    issuer_to_idp = get_issuer_to_idp()
    for issuer, idp_name in IssSubPairToUser.ISSUER_TO_IDP.items():
        logger.info(
            'Attempting to populate iss_sub_pair_to_user table for users with "{}" idp and "{}" issuer'.format(
                idp_name, issuer
            )
        )
        transaction = connection.begin()
        try:
            connection.execute(
                text(
                    """
                    WITH identity_provider_id AS (SELECT id FROM identity_provider WHERE name=:idp_name)
                    INSERT INTO iss_sub_pair_to_user (iss, sub, "fk_to_User", extra_info)
                    SELECT :iss, id_from_idp, id, additional_info
                    FROM "User"
                    WHERE idp_id IN (SELECT * FROM identity_provider_id) AND id_from_idp IS NOT NULL;
                    """
                ),
                idp_name=idp_name,
                iss=issuer,
            )
        except Exception as e:
            transaction.rollback()
            logger.warning(
                "Could not populate iss_sub_pair_to_user table: {}".format(e)
            )
        else:
            transaction.commit()
            logger.info("Population was successful")
