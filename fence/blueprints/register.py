"""
Endpoints for user registration.
Registration means that a user provides their name, org, and email,
in order to gain some predefined permissions.
"""

import flask
from flask_sqlalchemy_session import current_session

from fence import config
from fence.auth import login_required, admin_login_required
from fence.models import User

blueprint = flask.Blueprint("register-user", __name__)


@blueprint.route("/", methods=["GET", "POST"])
@login_required()
def register_user():
    """
    - If config["REGISTER_USERS_ON"] is True, then unregistered users are redirected
      here after logging in.
    - Users may then register or decline to register.
    - Users may access this endpoint directly if they initially declined to register.
    - At the moment, registration involves providing name, org, and (if user.email for
      the user is None) email.
    - If a user registers, add the new information to the user's additional_info column,
      and add the user to the Arborist group specified in
      config["REGISTERED_USERS_GROUP"].
      The idea is that users can register in order to obtain certain permissions (where
      the permissions are defined by the group definition in the useryaml).

    The registration info is added as a dict under user.additional_info["registration_info"];
    it is a separate blob in order to avoid namespace collision and make clear that the
    information was self-declared by the user during registration.

    The HTML form performs some dumb client-side validation, but actual verification
    (for example, checking organization info against some trusted authority's records)
    has been deemed out of scope.
    """
    if flask.request.method == "GET":
        on_decline_redirect = flask.session.get("redirect") or config["BASE_URL"]
        return flask.render_template(
            "register_user.html",
            user=flask.g.user,
            on_decline_redirect=on_decline_redirect,
        )

    assert flask.request.method == "POST"

    # HTML form should require all fields, so no gets.
    name = flask.request.form["name"]
    org = flask.request.form["organization"]

    if flask.g.user.email:
        # If user.email is populated, the form should not have had an email field.
        assert flask.request.form.get("email") is None
        email = flask.g.user.email
    else:
        email = flask.request.form["email"]

    combined_info = {}
    if flask.g.user.additional_info is not None:
        combined_info.update(flask.g.user.additional_info)
    registration_info = {
        "registration_info": {"name": name, "org": org, "email": email}
    }
    combined_info.update(registration_info)
    flask.g.user.additional_info = combined_info
    current_session.add(flask.g.user)
    current_session.commit()

    with flask.current_app.arborist.context():
        # make sure the user exists in Arborist
        flask.current_app.arborist.create_user(dict(name=flask.g.user.username))
        flask.current_app.arborist.add_user_to_group(
            flask.g.user.username,
            config["REGISTERED_USERS_GROUP"],
        )

    # Respect session redirect--important when redirected here from login flow
    if flask.session.get("redirect"):
        return flask.redirect(flask.session.get("redirect"))
    return flask.jsonify(registration_info)


@blueprint.route("/list", methods=["GET"])
@admin_login_required
def get_registered_users():
    """
    - List registration info for every user for which there exists registration info.
    - Endpoint accessible to admins only.
    - Response json structure is provisional.
    """
    registered_users = (
        current_session.query(User)
        .filter(User.additional_info["registration_info"] != "{}")
        .all()
    )
    registration_info_list = {
        u.username: u.additional_info["registration_info"] for u in registered_users
    }
    return registration_info_list
