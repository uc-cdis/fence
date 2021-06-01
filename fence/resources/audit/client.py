import boto3
import json
import requests
import time

from fence.config import config
from fence.errors import InternalError
from fence.resources.audit.utils import is_audit_enabled


class AuditServiceClient:
    def __init__(self, service_url, logger):
        self.service_url = service_url.rstrip("/")
        self.logger = logger
        self.push_type = config["PUSH_AUDIT_LOGS_CONFIG"].get("type", "api")

        # audit logs should not be enabled if the audit-service is unavailable
        if is_audit_enabled():
            logger.info("Enabling audit logs")
            self.ping()
            self.validate_config()
        else:
            logger.warning("NOT enabling audit logs")
            return

        if self.push_type == "aws_sqs":
            self.sqs = boto3.client(
                "sqs",
                region_name=config["PUSH_AUDIT_LOGS_CONFIG"]["region"],
                aws_access_key_id=config["PUSH_AUDIT_LOGS_CONFIG"].get(
                    "aws_access_key_id"
                ),
                aws_secret_access_key=config["PUSH_AUDIT_LOGS_CONFIG"].get(
                    "aws_secret_access_key"
                ),
            )

    def ping(self):
        max_tries = 3
        status_url = f"{self.service_url}/_status"
        self.logger.debug(f"Checking audit-service availability at {status_url}")
        wait_time = 1
        for t in range(max_tries):
            r = requests.get(status_url)
            if r.status_code == 200:
                return  # all good!
            if t + 1 < max_tries:
                self.logger.debug(f"Retrying... (got status code {r.status_code})")
                time.sleep(wait_time)
                wait_time *= 2
        raise Exception(
            f"Audit logs are enabled but audit-service is unreachable at {status_url}: {r.text}"
        )

    def validate_config(self):
        allowed_push_types = ["api", "aws_sqs"]
        if self.push_type not in allowed_push_types:
            raise Exception(
                f"Configured PUSH_AUDIT_LOGS_CONFIG.type '{self.push_type}' is not one of known types {allowed_push_types}"
            )

        if self.push_type == "aws_sqs":
            assert config["PUSH_AUDIT_LOGS_CONFIG"].get(
                "sqs_url"
            ), f"PUSH_AUDIT_LOGS_CONFIG.type is 'aws_sqs' but PUSH_AUDIT_LOGS_CONFIG.sqs_url is not configured"
            assert config["PUSH_AUDIT_LOGS_CONFIG"].get(
                "region"
            ), f"PUSH_AUDIT_LOGS_CONFIG.type is 'aws_sqs' but PUSH_AUDIT_LOGS_CONFIG.region is not configured"

    def check_response(self, resp, body):
        # The audit-service returns 201 before inserting the log in the DB.
        # This request should only error if the input is incorrect (status
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

    def create_audit_log(self, category, data):
        self.logger.debug(
            f"Creating {category} audit log (push type: {self.push_type})"
        )
        if self.push_type == "api":
            url = f"{self.service_url}/log/{category}"
            resp = requests.post(url, json=data)
            self.check_response(resp, data)
        elif self.push_type == "aws_sqs":
            data["category"] = category
            sqs_url = config["PUSH_AUDIT_LOGS_CONFIG"]["sqs_url"]
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
    ):
        if not is_audit_enabled("presigned_url"):
            return

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
        self.create_audit_log("presigned_url", data)

    def create_login_log(
        self,
        request_url,
        status_code,
        username,
        sub,
        idp,
        fence_idp=None,
        shib_idp=None,
        client_id=None,
    ):
        if not is_audit_enabled("login"):
            return

        # special case for idp=fence when falling back on
        # fence_idp=shibboleth and shib_idp=NIH
        if shib_idp == "None":
            shib_idp = None

        data = {
            "request_url": request_url,
            "status_code": status_code,
            "username": username,
            "sub": sub,
            "idp": idp,
            "fence_idp": fence_idp,
            "shib_idp": shib_idp,
            "client_id": client_id,
        }
        self.create_audit_log("login", data)
