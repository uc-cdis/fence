import flask
from functools import wraps
import traceback
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from cdislogging import get_logger

from fence.config import config


logger = get_logger(__name__)


def is_audit_enabled(category=None):
    enable_audit_logs = config["ENABLE_AUDIT_LOGS"] or {}
    if category:
        return enable_audit_logs and enable_audit_logs.get(category, False)
    return enable_audit_logs and any(v for v in enable_audit_logs.values())


def _clean_authorization_request_url(request_url):
    """
    Remove sensitive data from a login request URL.
    """
    parsed_url = urlparse(request_url)
    query_params = dict(parse_qsl(parsed_url.query, keep_blank_values=True))
    for param in ["code", "state"]:
        if param in query_params:
            query_params[param] = "redacted"
    url_parts = list(parsed_url)  # cast to list to override query params
    url_parts[4] = urlencode(query=query_params)
    request_url = urlunparse(url_parts)
    return request_url


def create_audit_log_for_request(response):
    """
    Right before returning the response to the user (see `after_this_request`
    in `enable_audit_logging` decorator), record an audit log. The data we
    need to record the logs are stored in `flask.g.audit_data` before reaching
    this code.
    """
    try:
        method = flask.request.method
        endpoint = flask.request.path
        audit_data = getattr(flask.g, "audit_data", {})
        request_url = endpoint
        if flask.request.query_string:
            # could use `flask.request.url` but we don't want the root URL
            request_url += f"?{flask.request.query_string.decode('utf-8')}"

        if method == "GET" and endpoint.startswith("/data/download/"):
            flask.current_app.audit_service_client.create_presigned_url_log(
                status_code=response.status_code,
                request_url=request_url,
                guid=endpoint[len("/data/download/") :],
                action="download",
                **audit_data,
            )
        elif method == "GET" and endpoint.startswith("/login/"):
            request_url = _clean_authorization_request_url(request_url)
            if audit_data:  # ignore login calls with no `username`/`sub`/`idp`
                flask.current_app.audit_service_client.create_login_log(
                    status_code=response.status_code,
                    request_url=request_url,
                    **audit_data,
                )
    except Exception:
        # TODO monitor this somehow
        traceback.print_exc()
        logger.error(f"!!! Unable to create audit log! Returning response anyway...")

    return response


def enable_audit_logging(f):
    """
    This decorator should be added to any API endpoint for which we
    record audit logs. It should not be added to non-audited endpoints,
    so that performance is not impacted.
    The `create_audit_log_for_request_decorator` decorator is only added
    if auditing is enabled, so that performance is not impacted when auditing
    is disabled.
    Possible improvement: pass a "category" argument to `is_audit_enabled`.

    /!\ This decorator is not enough to enable audit logging for an endpoint.
    Logic must be added to `create_audit_log_for_request()` and the audit
    service might need to be updated to handle new types of data.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        def create_audit_log_for_request_decorator(response):
            return create_audit_log_for_request(response)

        if is_audit_enabled():
            # we can't add the `after_this_request` and
            # `create_audit_log_for_request_decorator` decorators to the
            # functions directly, because `is_audit_enabled` depends on
            # the config being loaded
            flask.after_this_request(create_audit_log_for_request_decorator)
        return f(*args, **kwargs)

    return wrapper
