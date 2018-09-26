from cdiserrors import UnhealthyCheck
import flask

from fence.version_data import VERSION, COMMIT


def register_misc(app):
    @app.route("/_status", methods=["GET"])
    def health_check():
        """
        Health Check.
        """
        with flask.current_app.db.session as session:
            try:
                session.execute("SELECT 1")
            except Exception:
                raise UnhealthyCheck("Unhealthy")

        return "Healthy", 200

    @app.route("/_version", methods=["GET"])
    def version():
        """
        Return the version of this service.
        """

        base = {"version": VERSION, "commit": COMMIT}

        return flask.jsonify(base), 200
