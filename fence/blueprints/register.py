"""
Endpoints for user registration.
Registration means that a user provides their name, org, and email,
in order to gain some predefined permissions.
"""

import flask
from flask import current_app
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired, Email, StopValidation, ValidationError

from fence import config
from fence.auth import login_required
from fence.errors import UserError


blueprint = flask.Blueprint("register", __name__)


def xor_with_user_email(form, field):
    """
    Custom validator for the RegistrationForm email field.

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
            "Received unexpected 'email' field; this user is already associated with the "
            "email {}, so the form should not have had an email field".format(
                flask.g.user.email
            )
        )
    if flask.g.user.email and not field.data:
        # If user.email is non-empty, the form should not render an email field,
        # and empty field.data is expected--all good
        field.errors[:] = []
        raise StopValidation()


class RegistrationForm(FlaskForm):
    firstname = StringField(label="First Name", validators=[DataRequired()])
    lastname = StringField(label="Last Name", validators=[DataRequired()])
    organization = StringField(label="Organization", validators=[DataRequired()])
    email = StringField(
        label="Email", validators=[xor_with_user_email, Email(), DataRequired()]
    )


@blueprint.route("/", methods=["GET", "POST"])
@login_required()
def register_user():
    """
    - If config["REGISTER_USERS_ON"] is True, then unregistered users are redirected
      here after logging in.
    - Users may then register.
    - Users may access this endpoint directly.
    - At the moment, registration involves providing firstname, lastname, org, and
      (if user.email for the user is None) email.
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
        return flask.render_template(
            "register_user.html",
            user=flask.g.user,
            form=form,
        )

    if not form.validate():
        raise UserError("Form validation failed: {}".format(str(form.errors)))

    # Validation passed--don't check form data here.
    firstname = flask.request.form["firstname"]
    lastname = flask.request.form["lastname"]
    org = flask.request.form["organization"]
    email = flask.g.user.email or flask.request.form["email"]

    combined_info = {}
    if flask.g.user.additional_info is not None:
        combined_info.update(flask.g.user.additional_info)
    registration_info = {
        "registration_info": {
            "firstname": firstname,
            "lastname": lastname,
            "org": org,
            "email": email,
        }
    }
    combined_info.update(registration_info)
    flask.g.user.additional_info = combined_info
    current_app.scoped_session().add(flask.g.user)
    current_app.scoped_session().commit()

    with flask.current_app.arborist.context():
        # make sure the user exists in Arborist
        flask.current_app.arborist.create_user(dict(name=flask.g.user.username))
        if config["REGISTERED_USERS_GROUP"]:
            flask.current_app.arborist.add_user_to_group(
                flask.g.user.username,
                config["REGISTERED_USERS_GROUP"],
            )

    # Respect session redirect--important when redirected here from login flow
    if flask.session.get("redirect"):
        return flask.redirect(flask.session.get("redirect"))
    return flask.jsonify(registration_info)
