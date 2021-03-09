import flask
import requests
import time

from fence.config import config
from fence.errors import InternalError


class AuditServiceClient:
    def __init__(self, service_url, logger):
        self.service_url = service_url.rstrip("/")
        self.logger = logger

        # audit logs should not be enabled if the audit-service is unavailable
        if self.is_enabled():
            logger.info("Enabling audit logs")
            self.ping()
        else:
            logger.warn("NOT enabling audit logs")

    def is_enabled(self):
        enable_audit_logs = config.get("ENABLE_AUDIT_LOGS") or {}
        return enable_audit_logs and any(v for v in enable_audit_logs.values())

    def ping(self):
        max_tries = 3
        status_url = f"{self.service_url}/_status"
        self.logger.debug(f"Checking audit-service availability at {status_url}")
        for t in range(max_tries):
            r = requests.get(status_url)
            if r.status_code == 200:
                return  # all good!
            if t + 1 < max_tries:
                self.logger.debug(f"Retrying... (got status code {r.status_code})")
                time.sleep(1)
        raise Exception(
            f"Audit logs are enabled but audit-service is unreachable at {status_url}: {r.text}"
        )

    def check_response(self, resp, body):
        # The audit-service returns 201 before inserting the log in the DB.
        # This request should only error if the input is incorrect (status
        # code 422) or if the service is unreachable.
        if resp.status_code != 201:
            try:
                err = resp.json()
            except Exception:
                err = resp.text
            self.logger.error(f"Unable to POST audit log `{body}`. Details:\n{err}")
            raise InternalError("Unable to create audit log")

    def create_presigned_url_log(
        self,
        status_code,
        username,
        sub,
        guid,
        resource_paths,
        action,
        protocol,
    ):
        if not self.is_enabled():
            return

        request_url = ""
        if action == "download":
            request_url = f"/data/download/{guid}"
        else:
            self.logger.warning(
                f"Audit log `request_url` for action `{action}` is unknown"
            )

        url = f"{self.service_url}/log/presigned_url"
        body = {
            "request_url": request_url,
            "status_code": status_code,
            "username": username,
            "sub": sub,
            "guid": guid,
            "resource_paths": resource_paths,
            "action": action,
            "protocol": protocol,
        }
        resp = requests.post(url, json=body)
        self.check_response(resp, body)

    def create_login_log(
        self,
        status_code,
        username,
        sub,
        idp,
        fence_idp=None,
        shib_idp=None,
        client_id=None,
    ):
        if not self.is_enabled():
            return

        url = f"{self.service_url}/log/login"
        body = {
            "request_url": "TODO remove request_url?",
            "status_code": status_code,
            "username": username,
            "sub": sub,
            "idp": idp,
            "fence_idp": fence_idp,
            "shib_idp": shib_idp,
            "client_id": client_id,
        }
        resp = requests.post(url, json=body)
        self.check_response(resp, body)
