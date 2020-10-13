import uuid
from http.client import responses as http_responses
from flask import render_template
from werkzeug.exceptions import HTTPException

from authlib.oauth2.rfc6749.errors import OAuth2Error
from cdislogging import get_logger

from fence.errors import APIError
from fence.config import config


logger = get_logger(__name__)


def get_error_response(error):
    details, status_code = get_error_details_and_status(error)
    support_email = config.get("SUPPORT_EMAIL_FOR_ERRORS")
    app_name = config.get("APP_NAME", "Gen3 Data Commons")

    message = details.get("message")

    error_id = _get_error_identifier()
    logger.error(
        "{} HTTP error occured. ID: {}\nDetails: {}".format(
            status_code, error_id, str(details)
        )
    )

    # don't include internal details in the public error message
    # to do this, only include error messages for known http status codes
    # that are less that 500
    valid_http_status_codes = [
        int(code) for code in list(http_responses.keys()) if int(code) < 500
    ]
    try:
        status_code = int(status_code)
        if status_code not in valid_http_status_codes:
            message = None
    except (ValueError, TypeError):
        # this handles case where status_code is NOT a valid integer (e.g. HTTP status code)
        message = None
        status_code = 500

    status_code_message = http_responses.get(status_code, "Unknown error code.")

    return (
        render_template(
            "error.html",
            app_name=app_name,
            status_code=status_code,
            status_code_message=status_code_message,
            support_email=support_email,
            error_id=error_id,
            message=message,
        ),
        status_code,
    )


def get_error_details_and_status(error):
    message = error.message if hasattr(error, "message") else str(error)
    if isinstance(error, APIError):
        if hasattr(error, "json") and error.json:
            error.json["message"] = message
            error_response = error.json, error.code
        else:
            error_response = {"message": message}, error.code
    elif isinstance(error, OAuth2Error):
        error_response = {"message": error.description}, error.status_code
    elif isinstance(error, HTTPException):
        error_response = (
            {"message": getattr(error, "description")},
            error.get_response().status_code,
        )
    else:
        logger.exception("Catch exception")
        error_code = 500
        if hasattr(error, "code"):
            error_code = error.code
        elif hasattr(error, "status_code"):
            error_code = error.status_code
        error_response = {"message": message}, error_code

    return error_response


def _get_error_identifier():
    return uuid.uuid4()
