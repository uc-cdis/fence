# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch

from fence.scripting.google_monitor import validation_check
from fence.models import (
    UserServiceAccount, ServiceAccountAccessPrivilege,
    Bucket, Project, ProjectToBucket
)
from fence.resources.google.access_utils import (
    force_add_service_accounts_to_access
)


def test_validation_check_multiple_same_project(db_session, cloud_manager):
    registered_service_accounts = [
        '1@example.com', '2@example.com', '3@example.com'
    ]

    example_bucket = Bucket(name='bucket_1')
    db_session.add(example_bucket)
    db_session.commit()

    example_project = Project(
        name='Project 1',
        auth_id='project_1'
    )
    db_session.add(example_project)
    db_session.commit()

    link = ProjectToBucket(
        project_id=example_project.id,
        bucket_id=example_bucket.id
    )
    db_session.add(link)
    db_session.commit()

    force_add_service_accounts_to_access(
        service_account_emails=registered_service_accounts,
        google_project_id='google_project_x',
        project_access=['project_1']
    )

    validation_check(db=None)

    _assert_access('1@example.com', db_session)
    _assert_access('2@example.com', db_session)
    _assert_access('3@example.com', db_session)


def _assert_access(service_account_email, db_session, has_access=True):
    service_account = (
        db_session.query(UserServiceAccount)
        .filter_by(email=service_account_email).first()
    )
    assert service_account

    if has_access:
        assert (
            db_session.query(ServiceAccountAccessPrivilege)
            .filter_by(id=service_account.id)
        )
    else:
        assert not (
            db_session.query(ServiceAccountAccessPrivilege)
            .filter_by(id=service_account.id)
        )
