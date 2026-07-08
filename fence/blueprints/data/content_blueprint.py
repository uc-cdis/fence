import flask
from fence.blueprints.data.blueprint import get_file_content

blueprint = flask.Blueprint("data_content_only", __name__)
blueprint.add_url_rule("/content", view_func=get_file_content, methods=["POST"])
