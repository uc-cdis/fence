import flask


blueprint = flask.Blueprint('oauth', __name__)


@blueprint.route('/authorization_url', methods=['GET'])
def get_authorization_url():
    return flask.current_app.oauth2.authorize_url


@blueprint.route('/authorize', methods=['GET'])
def authorize():
    return flask.current_app.oauth2.authorize_redirect()


@blueprint.route('/token', methods=['GET'])
def token():
    return flask.current_app.oauth2.authorize_access_token()
