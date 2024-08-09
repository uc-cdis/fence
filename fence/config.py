import os
from yaml import safe_load as yaml_load
import urllib.parse

import gen3cirrus
from gen3config import Config

from cdislogging import get_logger
from collections import Counter
from typing import List, Dict, Any

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
        self._validate_dbgap_config(self._configs["dbGaP"])

    @staticmethod
    def find_duplicates(collection):
        """

        Args:
            collection: any data type accepted by the Counter object

        Returns:
            a set of items that were found more than once in the collection

        note: if collection is a set, this function will never find duplicates
        (per the definition of a set)
        """
        item_with_occurrences = Counter(collection)
        duplicates = {item
                      for item, occurrences in item_with_occurrences.items()
                      if occurrences > 1}
        return duplicates

    @staticmethod
    def get_parent_studies_safely(dbgap_config):
        """
        Args:
            dbgap_config: { parent_to_child_studies_mapping: { k1: v1, ... } }
        Returns:
            [k1, k2, ...]
        """
        study_mapping = dbgap_config.get('parent_to_child_studies_mapping', {})
        # study mapping could be 'None'
        safe_studies = list(study_mapping.keys()) if isinstance(study_mapping, dict) else []
        return safe_studies

    @staticmethod
    def validate_parent_child_studies(dbgap_configs: List[Dict[str, Any]]) -> None:
        """
        Given a list of dictionaries that contain a parent -> child study mapping,
        this function will check that all parents are unique and not duplicated
        Args:
            dbgap_configs: [ { parent_to_child_studies_mapping: { k1: v1, ... } }, ... ]

        Returns:
            Nothing. This function will throw if duplicates are found.
        """
        safe_list_of_parent_studies = []
        for dbgap_config in dbgap_configs:
            safe_parent_studies = FenceConfig.get_parent_studies_safely(dbgap_config)
            safe_list_of_parent_studies.extend(safe_parent_studies)

        duplicates = FenceConfig.find_duplicates(safe_list_of_parent_studies)
        if len(duplicates) > 0:
            raise Exception(
                f"{duplicates} are duplicate parent study ids found in parent_to_child_studies_mapping for "
                f"multiple dbGaP configurations.")

    @staticmethod
    def enforce_is_array(dbgap_configs):
        if isinstance(dbgap_configs, list):
            corrected_dbgap_configs = dbgap_configs
        elif isinstance(dbgap_configs, dict):
            corrected_dbgap_configs = [dbgap_configs]
        else:
            raise Exception("The dbgap configuration is not a recognized data structure, aborting!")
        return corrected_dbgap_configs

    @staticmethod
    def _validate_dbgap_config(dbgap_configs):
        corrected_dbgap_configs = FenceConfig.enforce_is_array(dbgap_configs)
        FenceConfig.validate_parent_child_studies(corrected_dbgap_configs)


config = FenceConfig(DEFAULT_CFG_PATH)
