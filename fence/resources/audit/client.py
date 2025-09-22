import backoff
import boto3
import json
import requests
import traceback
from cachelib import SimpleCache

from fence.config import config
from fence.errors import InternalError
from fence.resources.audit.utils import is_audit_enabled
from fence.utils import DEFAULT_BACKOFF_SETTINGS


AUDIT_SCHEMA_CACHE = SimpleCache(default_timeout=86400)  # cached for 24h


class AuditServiceClient:
    def __init__(self, service_url, logger):
        self.service_url = service_url.rstrip("/")
        self.logger = logger
        self.push_type = config["PUSH_AUDIT_LOGS_CONFIG"].get("type", "api")

        # audit logs should not be enabled if the audit-service is unavailable
        if is_audit_enabled():
            self.logger.info("Enabling audit logs")
            self._validate_config()
            try:
                self._ping()
            except Exception:
                if self.push_type == "api":
                    # the audit-service must be available when fence
                    # is configured to make API calls to it
                    raise
                else:
                    traceback.print_exc()
                    self.logger.warning(
                        "Audit logs are enabled but audit-service is unreachable. Continuing anyway..."
                    )
            self._set_schema_models_cache()
        else:
            self.logger.warning("NOT enabling audit logs")
            return

        if self.push_type == "aws_sqs":
            aws_sqs_config = config["PUSH_AUDIT_LOGS_CONFIG"]["aws_sqs_config"]
            # we know the cred is in AWS_CREDENTIALS (see `_check_buckets_aws_creds_and_region`)
            aws_creds = (
                config.get("AWS_CREDENTIALS", {})[aws_sqs_config["aws_cred"]]
                if "aws_cred" in aws_sqs_config
                else {}
            )
            if (
                not aws_creds
                and "aws_access_key_id" in aws_sqs_config
                and "aws_secret_access_key" in aws_sqs_config
            ):
                # for backwards compatibility
                aws_creds = {
                    "aws_access_key_id": aws_sqs_config["aws_access_key_id"],
                    "aws_secret_access_key": aws_sqs_config["aws_secret_access_key"],
                }
            self.sqs = boto3.client(
                "sqs",
                region_name=aws_sqs_config["region"],
                aws_access_key_id=aws_creds.get("aws_access_key_id"),
                aws_secret_access_key=aws_creds.get("aws_secret_access_key"),
            )

    @backoff.on_exception(backoff.expo, Exception, **DEFAULT_BACKOFF_SETTINGS)
    def _ping(self):
        """
        Hit the audit-service status endpoint.
        """
        status_url = f"{self.service_url}/_status"
        self.logger.debug(f"Checking audit-service availability at {status_url}")
        requests.get(status_url)

    @backoff.on_exception(backoff.expo, Exception, **DEFAULT_BACKOFF_SETTINGS)
    def _get_audit_schema(self):
        """
        Hit the audit-service _schema endpoint.
        """
        status_url = f"{self.service_url}/_schema"
        self.logger.info(f"Getting audit-service schema version at {status_url}")
        return requests.get(status_url)

    def _set_schema_models_cache(self):
        """
        Set schema versions/models in schema model cache if expired.
        """
        cache_key = "audit_schema"
        if not AUDIT_SCHEMA_CACHE.has(cache_key):
            resp = self._get_audit_schema()
            if resp.status_code == 200:
                schema = resp.json()
                self.logger.info(f"Setting audit schema cache: {schema}")
                AUDIT_SCHEMA_CACHE.set(cache_key, schema)
            elif resp.status_code == 404:
                schema = {
                    "login": {
                        "version": 1.0,
                        "model": {
                            "request_url": "str",
                            "status_code": "int",
                            "timestamp": "int",
                            "username": "str",
                            "sub": "int",
                            "idp": "str",
                            "fence_idp": "str?",
                            "shib_idp": "str?",
                            "client_id": "str?",
                        },
                    },
                    "presigned_url": {
                        "version": 1.0,
                        "model": {
                            "request_url": "str",
                            "status_code": "int",
                            "timestamp": "int",
                            "username": "str",
                            "sub": "int",
                            "guid": "str",
                            "resource_paths": "list",
                            "action": "str",
                            "protocol": "str",
                        },
                    },
                }
                self.logger.info(
                    f"/_schema endpoint {resp.status_code} – assuming version 1 for all audit log models: {schema}"
                )
                AUDIT_SCHEMA_CACHE.set(cache_key, schema)
            else:
                try:
                    err = resp.json()
                except Exception:
                    err = resp.text
                self.logger.error(
                    f"Unexpected response from audit schema endpoint. Status code: {resp.status_code} - Details:\n{err}"
                )
                raise InternalError("Unable to get audit schema")

    def _validate_config(self):
        """
        Validate the audit configuration, making sure required fields
        are populated.
        """
        allowed_push_types = ["api", "aws_sqs"]
        if self.push_type not in allowed_push_types:
            raise Exception(
                f"Configured PUSH_AUDIT_LOGS_CONFIG.type '{self.push_type}' is not one of known types {allowed_push_types}"
            )

        if self.push_type == "aws_sqs":
            aws_sqs_config = config["PUSH_AUDIT_LOGS_CONFIG"].get("aws_sqs_config", {})
            assert (
                aws_sqs_config
            ), f"PUSH_AUDIT_LOGS_CONFIG.type is 'aws_sqs' but PUSH_AUDIT_LOGS_CONFIG.aws_sqs_config is not configured"
            assert aws_sqs_config.get(
                "sqs_url"
            ), f"PUSH_AUDIT_LOGS_CONFIG.type is 'aws_sqs' but PUSH_AUDIT_LOGS_CONFIG.aws_sqs_config.sqs_url is not configured"
            assert aws_sqs_config.get(
                "region"
            ), f"PUSH_AUDIT_LOGS_CONFIG.type is 'aws_sqs' but PUSH_AUDIT_LOGS_CONFIG.aws_sqs_config.region is not configured"

    def _check_response(self, resp, body):
        """
        Check the status code after an audit log creation call, and in case
        of error, log details and raise an exception.

        Args:
            resp (requests.Response): response from the audit log creation call
            body (dict): audit log body for logging in case of error
        """
        # The audit-service returns 201 before inserting the log in the DB.
        # The requests should only error if the input is incorrect (status
        # code 422) or if the service is unreachable.
        if resp.status_code != 201:
            try:
                err = resp.json()
            except Exception:
                err = resp.text
            self.logger.error(
                f"Unable to POST audit log `{body}`. Status code: {resp.status_code} - Details:\n{err}"
            )
            raise InternalError("Unable to create audit log")

    def _create_audit_log(self, category, data):
        """
        Create an audit log - make an API call or push to a queue depending
        on the configuration.

        Args:
            category (str): audit log category
            data (dict): audit log data
        """
        self.logger.debug(
            f"Creating {category} audit log (push type: {self.push_type})"
        )
        if self.push_type == "api":
            url = f"{self.service_url}/log/{category}"
            resp = requests.post(url, json=data)
            self._check_response(resp, data)
        elif self.push_type == "aws_sqs":
            data["category"] = category
            sqs_url = config["PUSH_AUDIT_LOGS_CONFIG"]["aws_sqs_config"]["sqs_url"]
            try:
                self.sqs.send_message(QueueUrl=sqs_url, MessageBody=json.dumps(data))
            except Exception:
                self.logger.error(f"Error pushing audit log to SQS '{sqs_url}'")
                raise

    def create_presigned_url_log(
        self,
        request_url,
        status_code,
        username,
        sub,
        guid,
        action,
        resource_paths=None,
        protocol=None,
        additional_data=[],
    ):
        """
        Create a presigned URL audit log, or do nothing if auditing is
        disabled.

        Args: presigned URL audit log data fields
        """
        if not is_audit_enabled("presigned_url"):
            return

        self._set_schema_models_cache()

        data = {
            "request_url": request_url,
            "status_code": status_code,
            "username": username,
            "sub": sub,
            "guid": guid,
            "resource_paths": resource_paths,
            "action": action,
            "protocol": protocol,
        }

        if ("presigned_url" in AUDIT_SCHEMA_CACHE.get("audit_schema").keys()) and (
            "version"
            in AUDIT_SCHEMA_CACHE.get("audit_schema").get("presigned_url").keys()
        ):

            if (
                AUDIT_SCHEMA_CACHE.get("audit_schema")
                .get("presigned_url")
                .get("version")
                >= 1.1
            ):
                data["additional_data"] = additional_data

        else:
            self.logger.log(
                "Could not retrieve presigned_url version from audit schema"
            )

        self._create_audit_log("presigned_url", data)

    def create_login_log(
        self,
        request_url,
        status_code,
        username,
        sub,
        idp,
        upstream_idp=None,
        shib_idp=None,
        client_id=None,
        additional_data=[],
        ip=None,
    ):
        """
        Create a login audit log, or do nothing if auditing is disabled.

        Args: login audit log data fields
        """
        if not is_audit_enabled("login"):
            return

        self._set_schema_models_cache()

        # special case for idp=fence when falling back on
        # upstream_idp=shibboleth and shib_idp=NIH
        if shib_idp == "None":
            shib_idp = None

        data = {
            "request_url": request_url,
            "status_code": status_code,
            "username": username,
            "sub": sub,
            "idp": idp,
            # NOTE: audit-service still registers `upstream_idp` as `fence_idp`
            "fence_idp": upstream_idp,
            "shib_idp": shib_idp,
            "client_id": client_id,
        }

        if ("login" in AUDIT_SCHEMA_CACHE.get("audit_schema").keys()) and (
            "version" in AUDIT_SCHEMA_CACHE.get("audit_schema").get("login").keys()
        ):

            if (
                AUDIT_SCHEMA_CACHE.get("audit_schema").get("login").get("version")
                >= 2.1
            ):
                data["additional_data"] = additional_data

            if AUDIT_SCHEMA_CACHE.get("audit_schema").get("login").get("version") >= 2:
                data["ip"] = ip
        else:
            self.logger.log("Could not retrieve login version from audit schema")
            pass

        self._create_audit_log("login", data)
