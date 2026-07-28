"""
Temporary Example of a Resource Server enforcing DPoP
on an endpoint.
"""

import flask

from fence import config
from fence.errors import UserError

from authutils.dpop import validate_dpop_request, InvalidNonceErrorResourceServer

from cdislogging import get_logger

from fence.jwt.blacklist import is_blacklisted
from fence.jwt.errors import JWTError

logger = get_logger(__name__)

blueprint = flask.Blueprint("ga4gh", __name__)


@blueprint.route("/service-info", methods=["GET"])
@blueprint.route("/service-info/", methods=["GET"])
async def service_info() -> dict:
    """
    Get details about the GA4GH TES server
    """
    return {}


@blueprint.route("/tes/v1", methods=["GET", "POST", "PUT", "DELETE"])
@blueprint.route("/tes/v1/", methods=["GET", "POST", "PUT", "DELETE"])
@blueprint.route("/tes/v1/{path}", methods=["GET", "POST", "PUT", "DELETE"])
def tes(path: str | None = None) -> flask.Response:
    # For the header: the underlying flask library handles case-insensitivity required
    dpop_header = flask.request.headers.get("DPoP", "")

    request_method = flask.request.method
    request_url = flask.request.base_url

    # Get the unvalidated access token from the request Authorization header
    unvalidated_access_token = flask.request.headers.get("Authorization", "")
    unvalidated_access_token = unvalidated_access_token.replace("Bearer ", "").replace(
        "bearer ", ""
    )

    # Get issuers from config for DPoP validation
    # TODO: Update for other services
    issuers = [config["BASE_URL"]]

    try:
        dpop_claims, access_token_claims, client_jwk = validate_dpop_request(
            dpop_header=dpop_header,
            access_token=unvalidated_access_token,
            request_method=request_method,
            request_url=request_url,
            issuers=issuers,
            scope={"openid"},
            purpose="access",
            aud="WORKFLOW",
            require_nonce=True,
            # TODO: change to API call to Fence
            denylist_callback=is_blacklisted,
            secret=config["DPOP_SHARED_SECRET"],
        )
    except InvalidNonceErrorResourceServer as invalid_nonce_error:
        logger.debug(f"invalid_nonce_error. Returning with server-provided nonce...")
        # early error return with new nonce for client to resend
        response = flask.jsonify(invalid_nonce_error.json)
        response.status_code = int(invalid_nonce_error.code)
        for key, value in invalid_nonce_error.error_headers.items():
            response.headers[key] = value
        return response
    except (JWTError, ValueError) as exc:
        # TODO: use service-specific error
        raise UserError("Invalid DPoP request")
    except Exception as exc:
        logger.error(f"Unknown error validating DPoP request: {exc}")
        # TODO: use service-specific error
        raise UserError("Error validating DPoP request")

    return flask.jsonify({"success": True})
