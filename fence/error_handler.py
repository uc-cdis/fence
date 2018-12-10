import uuid
from httplib import responses as http_responses

import flask
from flask import render_template
from authlib.specs.rfc6749.errors import OAuth2Error
from werkzeug.exceptions import HTTPException

from fence.errors import APIError
from fence.config import config


def get_error_response(error):
    details, status_code = get_error_details_and_status(error)
    support_email = config.get("SUPPORT_EMAIL_FOR_ERRORS")
    app_name = config.get("APP_NAME", "Gen3 Data Commons")

    message = details.get("message")

    error_id = _get_error_identifier()
    flask.current_app.logger.error(
        "{} HTTP error occured. ID: {}\nDetails: {}".format(
            status_code, error_id, str(details)
        )
    )

    # don't include internal details in the public error message
    if status_code == 500:
        message = None

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
    if isinstance(error, APIError):
        if hasattr(error, "json") and error.json:
            error.json["message"] = error.message
            error_response = error.json, error.code
        else:
            error_response = {"message": error.message}, error.code
    elif isinstance(error, OAuth2Error):
        error_response = {"message": error.description}, error.status_code
    elif isinstance(error, HTTPException):
        error_response = (
            {"message": getattr(error, "description")},
            error.get_response().status_code,
        )
    else:
        flask.current_app.logger.exception("Catch exception")
        error_code = 500
        if hasattr(error, "code"):
            error_code = error.code
        elif hasattr(error, "status_code"):
            error_code = error.status_code
        error_response = {"message": error.message}, error_code

    return error_response


def _get_error_identifier():
    return uuid.uuid4()
