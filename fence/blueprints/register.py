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

from cdislogging import get_logger

from fence import config
from fence.errors import Unauthorized, UserError
from fence.models import query_for_user


logger = get_logger(__name__)
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
    # TODO what happens if registration fails? infinite redirects between login and registration?
    form = RegistrationForm()

    # can't use the @login_required() decorator here to enforce logging in, because at this
    # point in the flow the user should have _started_ logging in, but may not be logged in
    # yet
    user_tuple = flask.session.get("login_in_progress_user")
    if not user_tuple:
        raise Unauthorized("Please login")
    _, username = user_tuple

    if flask.request.method == "GET":
        user = query_for_user(session=current_app.scoped_session(), username=username)
        return flask.render_template(
            "register_user.html",
            user=user,
            form=form,
        )

    # TODO fix: doesn’t accept email addresses if they have leading or trailing spaces
    # if not form.validate():
    #     raise UserError("Form validation failed: {}".format(str(form.errors)))

    # Validation passed--don't check form data here.
    firstname = flask.request.form["firstname"]
    lastname = "x"  # flask.request.form["lastname"]
    org = "x"  # flask.request.form["organization"]
    email = "x"  # flask.g.user.email or flask.request.form["email"]

    registration_info = add_user_registration_info_to_database(
        username, firstname, lastname, org, email
    )

    # Respect session redirect--important when redirected here from login flow
    if flask.session.get("post_registration_redirect"):
        return flask.redirect(flask.session.get("post_registration_redirect"))
    return flask.jsonify(registration_info)


def add_user_registration_info_to_database(
    username, firstname, lastname, organization, email
):
    user = query_for_user(session=current_app.scoped_session(), username=username)
    user.additional_info = user.additional_info or {}
    registration_info = {
        "firstname": firstname,
        "lastname": lastname,
        "org": organization,
        "email": email,
    }
    user.additional_info["registration_info"] = registration_info
    current_app.scoped_session().add(user)
    current_app.scoped_session().commit()

    if flask.current_app.arborist:
        with flask.current_app.arborist.context():
            # make sure the user exists in Arborist
            flask.current_app.arborist.create_user(dict(name=user.username))
            if config["REGISTERED_USERS_GROUP"]:
                # TODO unit tests
                arborist_groups = set(
                    g["name"]
                    for g in flask.current_app.arborist.list_groups().get("groups", [])
                )
                if config["REGISTERED_USERS_GROUP"] not in arborist_groups:
                    logger.debug(
                        f"Configured REGISTERED_USERS_GROUP '{config['REGISTERED_USERS_GROUP']}' does not exist yet. Creating it (it will have no policies)."
                    )
                    flask.current_app.arborist.put_group(
                        config["REGISTERED_USERS_GROUP"]
                    )
                success = flask.current_app.arborist.add_user_to_group(
                    user.username,
                    config["REGISTERED_USERS_GROUP"],
                )
                assert success is True, "Unable to add user to group"

    return registration_info
