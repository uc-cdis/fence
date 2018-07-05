import flask
import flask_restful
from authlib.specs.rfc6749.errors import OAuth2Error
from werkzeug.exceptions import HTTPException

from fence.errors import APIError
from fence.utils import append_query_params


class RestfulApi(flask_restful.Api):

    def handle_error(self, e):
        return handle_error(e)


def handle_error(error):
    """
    Register an error handler for general exceptions.
    """
    error_response = None

    if isinstance(error, APIError):
        if hasattr(error, 'json') and error.json:
            error.json['message'] = error.message
            error_response = error.json, error.code
        else:
            error_response = {'message': error.message}, error.code
    elif isinstance(error, OAuth2Error):
        error_response = {'message': error.description}, error.status_code
    elif isinstance(error, HTTPException):
        error_response = (
            {'message': getattr(error, 'description')},
            error.get_response().status_code
        )
    else:
        flask.current_app.logger.exception("Catch exception")
        error_code = 500
        if hasattr(error, 'code'):
            error_code = error.code
        elif hasattr(error, 'status_code'):
            error_code = error.status_code
        error_response = {'message': error.message}, error_code

    redirect = _get_redirect()
    if redirect:
        error_class = _get_full_class_name(error)
        error_description = error_response[0].get('message')
        redirect_with_error = append_query_params(
            redirect, error=error_class,
            error_description=error_description)
        error_response = flask.redirect(redirect_with_error)
    else:
        error_response = flask.jsonify(error_response[0]), error_response[1]

    return error_response


def _get_redirect():
    """
    Return a redirect if one is in the args or session
    """
    redirect = _get_redirect_from_args()
    if not redirect:
        redirect = _get_redirect_from_session()
    return redirect


def _get_redirect_from_args():
    """
    Return a redirect if a redirect argument exists request
    """
    redirect = None
    if flask.request.args.get('redirect'):
        redirect = flask.request.args.get('redirect')
    elif flask.request.args.get('redirect_uri'):
        redirect = flask.request.args.get('redirect_uri')
    elif flask.request.args.get('next'):
        redirect = flask.request.args.get('next')
    elif flask.request.args.get('redirect_url'):
        redirect = flask.request.args.get('redirect_url')
    elif flask.request.args.get('AppReturnUrl'):
        redirect = flask.request.args.get('AppReturnUrl')
    return redirect


def _get_redirect_from_session():
    """
    Return a redirect if the session has one
    """
    redirect = None
    if 'redirect' in flask.session:
        redirect = flask.session['redirect']
    return redirect


def _get_full_class_name(some_object):
    parent_module_path = str(getattr(some_object, '__module__', ''))
    class_name = str(some_object.__class__.__name__)
    if parent_module_path:
        full_class_name = parent_module_path + '.' + class_name
    else:
        full_class_name = class_name

    return full_class_name
