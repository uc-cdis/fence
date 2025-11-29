from __future__ import annotations
import os
from flask import Flask, jsonify

from .models import init_db
from .admin_routes import bp as admin_bp

def create_app() -> Flask:
    """
    Create and configure the Flask application.

    Returns:
        Flask: The configured Flask application instance.
    """
    app = Flask(__name__)
    app.register_blueprint(admin_bp)

    @app.get("/healthz")
    def health() -> 'flask.Response':
        """
        Health check endpoint.

        Returns:
            flask.Response: JSON response indicating service health.
        """
        return jsonify({"ok": True})

    return app

if __name__ == "__main__":
    init_db()
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
