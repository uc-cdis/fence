"""
Endpoints for user registration.
Registration means that a user provides their name, org, and email,
in order to gain some predefined permissions.
"""

import flask
from flask import current_app
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired, Email, ValidationError

from cdislogging import get_logger

from fence import config
from fence.errors import Unauthorized, UserError
from fence.models import query_for_user, User


logger = get_logger(__name__)
blueprint = flask.Blueprint("register", __name__)


class RegistrationForm(FlaskForm):
    firstname = StringField(label="First Name", validators=[DataRequired()])
    lastname = StringField(label="Last Name", validators=[DataRequired()])
    organization = StringField(label="Organization", validators=[DataRequired()])
    email = StringField(
        label="Email",
        validators=[Email(), DataRequired()],
        # avoid validation errors when the email address has trailing spaces:
        filters=[lambda s: s.strip() if s else s],
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
    form = RegistrationForm()

    if hasattr(flask.g, "user") and flask.g.user:
        user = flask.g.user
    else:
        username = flask.session.get("login_in_progress_username")
        # can't use the @login_required() decorator here to enforce logging in, because at this
        # point in the flow the user should have _started_ logging in, but may not be logged in
        # yet
        if not username:
            raise Unauthorized("Please login")
        user = query_for_user(session=current_app.scoped_session(), username=username)
        if not user:
            raise Exception(
                "User should already exist in the database when accessing /register"
            )

    if flask.request.method == "GET":
        return flask.render_template(
            "register_user.html",
            user=user,
            form=form,
        )

    # Our current registration policy is that if user.email is present from the IdP,
    # then use that email; otherwise ask for email at registration.
    # Therefore the HTML/jinja form will render an email field only if user.email is None,
    # and we check that one and only one of user.email or form.email is non-empty.
    if user.email:
        if flask.request.form.get("email"):
            raise ValidationError(
                "Received unexpected 'email' field; this user is already associated with the "
                "email '{}', so the form should not have had an email field".format(
                    user.email
                )
            )
        form.email.validators = []  # do not validate the email field

    if not form.validate():
        raise UserError("Form validation failed: {}".format(str(form.errors)))

    # Validation passed--don't check form data here.
    firstname = flask.request.form["firstname"].strip()
    lastname = flask.request.form["lastname"].strip()
    org = flask.request.form["organization"].strip()
    email = user.email or flask.request.form["email"].strip()

    registration_info = add_user_registration_info_to_database(
        user, firstname, lastname, org, email
    )

    # Respect session redirect--important when redirected here from login flow
    if flask.session.get("post_registration_redirect"):
        return flask.redirect(flask.session.get("post_registration_redirect"))
    return flask.jsonify(registration_info)


def add_user_registration_info_to_database(
    user: User, firstname: str, lastname: str, organization: str, email: str
):
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
