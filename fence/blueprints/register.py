"""
Endpoints for user registration.
Registration means that a user provides their name, org, and email,
in order to gain some predefined permissions.
"""

import flask
from flask_sqlalchemy_session import current_session
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired, Email, StopValidation, ValidationError

from fence import config
from fence.auth import login_required, admin_login_required
from fence.errors import UserError
from fence.models import User


blueprint = flask.Blueprint("register-user", __name__)


class RegistrationForm(FlaskForm):
    def EmailSometimesRequired(form, field):
        """
        Our current registration policy is that if user.email is present from the IdP,
        then use that email; otherwise ask for email at registration.

        Therefore the HTML/jinja form will render an email field only if user.email is None,
        and this validator will check that one and only one of user.email or field.data
        is non-empty.
        """
        if not flask.g.user.email and not field.data:
            raise ValidationError("Email field is required")
        if flask.g.user.email and field.data:
            raise ValidationError(
                "This user is connected to the email {} and the form should "
                "not have an email field".format(flask.g.user.email)
            )
        if flask.g.user.email and not field.data:
            # If user.email is non-empty, the form should not render an email field,
            # and empty field.data is expected--all good
            field.errors[:] = []
            raise StopValidation()

    name = StringField(label="Name", validators=[DataRequired()])
    organization = StringField(label="Organization", validators=[DataRequired()])
    email = StringField(label="Email", validators=[EmailSometimesRequired, Email()])


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

    Some basic validation is done on form inputs (non-empty fields, plausible emails),
    but actual verification (for example, checking organization info against some trusted
    authority's records) has been deemed out of scope.
    """
    form = RegistrationForm()

    if flask.request.method == "GET":
        on_decline_redirect = flask.session.get("redirect") or config["BASE_URL"]
        return flask.render_template(
            "register_user.html",
            user=flask.g.user,
            on_decline_redirect=on_decline_redirect,
            form=form,
        )

    assert flask.request.method == "POST"

    if not form.validate():
        raise UserError("Form validation failed: {}".format(str(form.errors)))

    # Validation passed--don't check form data here.
    name = flask.request.form["name"]
    org = flask.request.form["organization"]
    email = flask.g.user.email or flask.request.form["email"]

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
