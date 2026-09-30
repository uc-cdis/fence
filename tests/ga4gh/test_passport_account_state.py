"""
Resolving a visa identity to a Fence user grants that user's access and refreshes their
arborist policies, so it has to honor the same account-state decisions the login path
makes: a deactivated account stays deactivated, and a deployment that does not admit
new users on login does not gain them here either.
"""

import time

import jwt
import pytest

from fence.config import config
from fence.errors import Unauthorized
from fence.models import query_for_user
from fence.resources.ga4gh.passports import get_or_create_gen3_user_from_iss_sub


ISSUER = "https://stsstg.nih.gov"
SUBJECT_ID = "account-state-subject"
USERNAME = SUBJECT_ID + ISSUER[len("https://") :]


def test_new_user_is_created_when_allowed(app, db_session):
    """With new users allowed on login, an unseen visa identity gets an account."""
    with app.app_context():
        user = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )

    assert user.username == USERNAME


def test_existing_active_user_is_returned(app, db_session):
    """An active account is resolved on a later request."""
    with app.app_context():
        created = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )
        db_session.commit()

        resolved = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )

    assert resolved.id == created.id


def test_deactivated_user_is_refused(app, db_session):
    """A deactivated account is not resolved, so its access is not refreshed."""
    with app.app_context():
        user = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )
        user.active = False
        db_session.commit()

        with pytest.raises(Unauthorized):
            get_or_create_gen3_user_from_iss_sub(
                ISSUER, SUBJECT_ID, db_session=db_session
            )


def test_new_user_is_not_created_when_disallowed(app, db_session, monkeypatch):
    """
    With ALLOW_NEW_USER_ON_LOGIN off, an unseen visa identity does not get an account.

    The config comment for that setting promises the user can only log in once added
    to the Fence database by a separate process, which this path would otherwise
    sidestep entirely.
    """
    monkeypatch.setitem(config, "ALLOW_NEW_USER_ON_LOGIN", False)

    with app.app_context():
        with pytest.raises(Unauthorized):
            get_or_create_gen3_user_from_iss_sub(
                ISSUER, SUBJECT_ID, db_session=db_session
            )

        assert not query_for_user(session=db_session, username=USERNAME)


def test_existing_user_still_resolves_when_new_users_disallowed(
    app, db_session, monkeypatch
):
    """
    ALLOW_NEW_USER_ON_LOGIN gates creation only, not resolution.

    Guards against the new check being written so broadly that it locks out the
    pre-registered users such a deployment does expect to serve.
    """
    with app.app_context():
        created = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )
        db_session.commit()

        monkeypatch.setitem(config, "ALLOW_NEW_USER_ON_LOGIN", False)
        resolved = get_or_create_gen3_user_from_iss_sub(
            ISSUER, SUBJECT_ID, db_session=db_session
        )

    assert resolved.id == created.id
