import flask
import requests
import time

from fence.config import config
from fence.errors import InternalError


def get_request_url():
    request_url = flask.request.url
    base_url = config.get("BASE_URL", "")
    if request_url.startswith(base_url):
        request_url = request_url[len(base_url) :]
    return request_url


def is_audit_enabled(category=None):
    enable_audit_logs = config.get("ENABLE_AUDIT_LOGS") or {}
    if category:
        return enable_audit_logs and enable_audit_logs.get(category, False)
    return enable_audit_logs and any(v for v in enable_audit_logs.values())


class AuditServiceClient:
    def __init__(self, service_url, logger):
        self.service_url = service_url.rstrip("/")
        self.logger = logger

        # audit logs should not be enabled if the audit-service is unavailable
        if is_audit_enabled():
            logger.info("Enabling audit logs")
            self.ping()
        else:
            logger.warn("NOT enabling audit logs")

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
        username,
        sub,
        guid,
        resource_paths,
        action,
        protocol,
    ):
        if not is_audit_enabled("presigned_url"):
            return

        url = f"{self.service_url}/log/presigned_url"
        body = {
            "request_url": get_request_url(),
            "status_code": 200,  # only record successful requests for now
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

        url = f"{self.service_url}/log/login"
        body = {
            "request_url": get_request_url(),
            "status_code": 200,  # only record successful requests for now
            "username": username,
            "sub": sub,
            "idp": idp,
            "fence_idp": fence_idp,
            "shib_idp": shib_idp,
            "client_id": client_id,
        }
        resp = requests.post(url, json=body)
        self.check_response(resp, body)
