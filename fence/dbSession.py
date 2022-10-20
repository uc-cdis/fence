from flask import _app_ctx_stack, current_app
from werkzeug.local import LocalProxy

##############################################
# This is a workaround for this issue: https://github.com/dtheodor/flask-sqlalchemy-session/issues/14
# werkzeug was updated 2.1.0 and deprecated __ident_func__, used in flask-sqlalchemy-session library
# replacement for: from flask_sqlalchemy_session import flask_scoped_session, current_session
##############################################


def _get_session():
    # pylint: disable=missing-docstring, protected-access
    context = _app_ctx_stack.top
    if context is None:
        raise RuntimeError(
            "Cannot access current_session when outside of an application " "context."
        )
    app = current_app._get_current_object()
    if not hasattr(app, "scoped_session"):
        raise AttributeError(
            "{0} has no 'scoped_session' attribute. You need to initialize it "
            "with a flask_scoped_session.".format(app)
        )
    return app.scoped_session


current_session = LocalProxy(_get_session)
