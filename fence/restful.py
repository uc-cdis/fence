import flask
import flask_restful
from authlib.specs.rfc6749.errors import OAuth2Error

from fence.errors import APIError


class RestfulApi(flask_restful.Api):

    def handle_error(self, e):
        return handle_error(e)
        # flask_restful.abort(e.code, str(e))
        #


def handle_error(error):
    """
    Register an error handler for general exceptions.
    """
    if isinstance(error, APIError):
        if hasattr(error, 'json') and error.json:
            return flask.jsonify(**error.json), error.code
        else:
            return flask.jsonify(message=error.message), error.code
    elif isinstance(error, OAuth2Error):
        return flask.jsonify(error.get_body()), error.status_code
    else:
        flask.current_app.logger.exception("Catch exception")
        return flask.jsonify(error=error.message), 500
