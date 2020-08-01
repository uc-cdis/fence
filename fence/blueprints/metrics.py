"""
This blueprint defines the /metrics enpdoint to serve a placeholder
to host fence metrics that will be added later on
"""

import flask

blueprint = flask.Blueprint("metrics", __name__)


@blueprint.route("/", methods=["GET"])
def metrics():
    payload = """
# HELP metric_placeholder sample metric here
# TYPE metric_placeholder gauge
metric_placeholder{sample_label="labelA"} 1.0
"""
    response = make_response(payload, 200)
    response.mimetype = "text/plain"
    return response
