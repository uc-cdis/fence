import flask
import requests

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
            logger.info("NOT enabling audit logs")

    def is_enabled(self):
        enable_audit_logs = config.get("ENABLE_AUDIT_LOGS") or {}
        return enable_audit_logs and any(v for v in enable_audit_logs.values())

    def ping(self):
        self.logger.debug("Checking audit-service availability...")
        status_url = f"{self.service_url}/_status"
        r = requests.get(status_url)
        assert (
            r.status_code == 200
        ), f"audit-service is unreachable at {status_url}: {r.text}"

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
