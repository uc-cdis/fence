from addict import Dict
import jwt
import pytest
import time
import random
import string

from fence.models import (
    AccessPrivilege,
    User,
    UserGoogleAccount,
    Project,
    ProjectToBucket,
    Bucket,
    ProjectToBucket,
    CloudProvider,
    UserServiceAccount,
    ServiceAccountToGoogleBucketAccessGroup,
    GoogleBucketAccessGroup,
    ServiceAccountAccessPrivilege,
)

from tests import utils

from flask_sqlalchemy_session import current_session

from userdatamodel.models import Project, Bucket, ProjectToBucket
from fence.models import GoogleBucketAccessGroup

from fence.resources.google.validity import GoogleServiceAccountValidity

from unittest.mock import MagicMock, patch


@pytest.fixture(scope="function")
def encoded_jwt_service_accounts_access(
    kid, rsa_private_key, user_client, oauth_client
):
    """
    Return a JWT and user_id for a new user containing the claims and
    encoded with the private key.

    Args:
        claims (dict): fixture
        rsa_private_key (str): fixture

    Return:
        str: JWT containing claims encoded with private key
    """
    headers = {"kid": kid}
    return Dict(
        jwt=jwt.encode(
            utils.authorized_service_account_management_claims(
                user_client["username"],
                user_client["user_id"],
                oauth_client["client_id"],
            ),
            key=rsa_private_key,
            headers=headers,
            algorithm="RS256",
        ).decode("utf-8"),
        user_id=user_client["user_id"],
        client_id=oauth_client["client_id"],
    )


@pytest.fixture(scope="function")
def valid_service_account_patcher():
    patches = []

    valid_type_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.access_utils.is_valid_service_account_type",
            valid_type_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.validity.is_valid_service_account_type",
            valid_type_mock,
        )
    )

    external_access_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.access_utils.service_account_has_external_access",
            external_access_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.validity.service_account_has_external_access",
            external_access_mock,
        )
    )

    from_google_project_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.access_utils.is_service_account_from_google_project",
            from_google_project_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.validity.is_service_account_from_google_project",
            from_google_project_mock,
        )
    )

    get_policy_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.access_utils.get_service_account_policy",
            get_policy_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.validity.get_service_account_policy",
            get_policy_mock,
        )
    )

    valid_type_mock.return_value = True
    external_access_mock.return_value = False
    from_google_project_mock.return_value = True
    get_policy_mock.return_value = None

    for patched_function in patches:
        patched_function.start()

    yield {
        "is_valid_service_account_type": (valid_type_mock),
        "service_account_has_external_access": (external_access_mock),
        "is_service_account_from_google_project": (from_google_project_mock),
        "get_service_account_policy": (get_policy_mock),
    }

    for patched_function in patches:
        patched_function.stop()


@pytest.fixture(scope="function")
def valid_google_project_patcher():
    patches = []

    get_project_number_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.access_utils.get_google_project_number",
            get_project_number_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.validity.get_google_project_number",
            get_project_number_mock,
        )
    )

    parent_org_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.access_utils.get_google_project_parent_org",
            parent_org_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.validity.get_google_project_parent_org",
            parent_org_mock,
        )
    )

    valid_membership_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.access_utils.get_google_project_valid_users_and_service_accounts",
            valid_membership_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.validity.get_google_project_valid_users_and_service_accounts",
            valid_membership_mock,
        )
    )

    get_users_from_members_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.access_utils.get_users_from_google_members",
            get_users_from_members_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.validity.get_users_from_google_members",
            get_users_from_members_mock,
        )
    )

    remove_white_listed_accounts_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.access_utils.remove_white_listed_service_account_ids",
            remove_white_listed_accounts_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.validity.remove_white_listed_service_account_ids",
            remove_white_listed_accounts_mock,
        )
    )

    users_have_access_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.access_utils.do_all_users_have_access_to_project",
            users_have_access_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.validity.do_all_users_have_access_to_project",
            users_have_access_mock,
        )
    )

    get_registered_service_accounts_with_access_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.validity.get_registered_service_accounts_with_access",
            get_registered_service_accounts_with_access_mock,
        )
    )

    project_access_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.validity.get_project_access_from_service_accounts",
            project_access_mock,
        )
    )

    project_service_accounts_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.validity.get_service_account_ids_from_google_members",
            project_service_accounts_mock,
        )
    )

    user_has_access_mock = MagicMock()
    patches.append(
        patch(
            "fence.resources.google.access_utils.is_user_member_of_all_google_projects",
            user_has_access_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.validity.is_user_member_of_all_google_projects",
            user_has_access_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.access_utils.is_user_member_of_google_project",
            user_has_access_mock,
        )
    )
    patches.append(
        patch(
            "fence.resources.google.validity.is_user_member_of_google_project",
            user_has_access_mock,
        )
    )

    get_project_number_mock.return_value = 1
    parent_org_mock.return_value = None
    valid_membership_mock.return_value = [], []
    get_users_from_members_mock.return_value = []
    users_have_access_mock.return_value = True
    project_service_accounts_mock.return_value = []
    user_has_access_mock.return_value = True

    for patched_function in patches:
        patched_function.start()

    yield {
        "get_google_project_number": (get_project_number_mock),
        "get_google_project_parent_org": (parent_org_mock),
        "get_google_project_valid_users_and_service_accounts": (valid_membership_mock),
        "get_users_from_google_members": (get_users_from_members_mock),
        "remove_white_listed_service_account_ids": (remove_white_listed_accounts_mock),
        "do_all_users_have_access_to_project": (users_have_access_mock),
        "get_registered_service_accounts_with_access": (
            get_registered_service_accounts_with_access_mock
        ),
        "get_project_access_from_service_accounts": (project_access_mock),
        "get_service_account_ids_from_google_members": (project_service_accounts_mock),
    }

    for patched_function in patches:
        patched_function.stop()


@pytest.fixture(scope="function")
def setup_data(db_session):
    cp = CloudProvider(name="test", endpoint="http://test.endpt")
    user = UserServiceAccount(
        google_unique_id="test_id", email="test@gmail.com", google_project_id="test"
    )
    user_1 = UserServiceAccount(
        google_unique_id="test_id", email="1@example.com", google_project_id="test"
    )
    user_2 = UserServiceAccount(
        google_unique_id="test_id", email="2@example.com", google_project_id="test"
    )
    user_3 = UserServiceAccount(
        google_unique_id="test_id", email="3@example.com", google_project_id="test"
    )

    db_session.add(user)
    db_session.add(user_1)
    db_session.add(user_2)
    db_session.add(user_3)

    db_session.add(cp)
    db_session.commit()

    bucket = Bucket(name="bucket1", provider_id=cp.id)
    bucket2 = Bucket(name="bucket2", provider_id=cp.id)
    bucket3 = Bucket(name="bucket3", provider_id=cp.id)

    db_session.add(bucket)
    db_session.add(bucket2)
    db_session.add(bucket3)
    db_session.commit()

    project1 = Project(name="test_1", auth_id="test_auth_1")
    project2 = Project(name="test_2", auth_id="test_auth_2")
    project3 = Project(name="test_3", auth_id="test_auth_3")
    db_session.add(project1)
    db_session.add(project2)
    db_session.add(project3)
    db_session.commit()

    db_session.add(ProjectToBucket(project_id=project1.id, bucket_id=bucket.id))
    db_session.add(ProjectToBucket(project_id=project2.id, bucket_id=bucket2.id))
    db_session.add(ProjectToBucket(project_id=project3.id, bucket_id=bucket3.id))

    db_session.add(
        ServiceAccountAccessPrivilege(
            project_id=project1.id, service_account_id=user.id
        )
    )
    db_session.add(
        ServiceAccountAccessPrivilege(
            project_id=project2.id, service_account_id=user.id
        )
    )

    db_session.add(
        ServiceAccountAccessPrivilege(
            project_id=project1.id, service_account_id=user_1.id
        )
    )
    db_session.add(
        ServiceAccountAccessPrivilege(
            project_id=project1.id, service_account_id=user_2.id
        )
    )
    db_session.add(
        ServiceAccountAccessPrivilege(
            project_id=project1.id, service_account_id=user_3.id
        )
    )

    access_grp = GoogleBucketAccessGroup(
        bucket_id=bucket.id, email="access_grp_test1@gmail.com"
    )

    access_grp2 = GoogleBucketAccessGroup(
        bucket_id=bucket2.id, email="access_grp_test2@gmail.com"
    )

    access_grp3 = GoogleBucketAccessGroup(
        bucket_id=bucket3.id, email="access_grp_test3@gmail.com"
    )

    db_session.add(access_grp)
    db_session.add(access_grp2)
    db_session.add(access_grp3)
    db_session.commit()

    service_account_grp1 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=user.id, access_group_id=access_grp.id
    )

    service_account_grp2 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=user.id, access_group_id=access_grp2.id
    )
    db_session.add(service_account_grp1)
    db_session.add(service_account_grp2)
    db_session.commit()


@pytest.fixture(scope="function")
def register_user_service_account(db_session):
    cp = db_session.query(CloudProvider).filter_by(name="test").first()
    if not cp:
        cp = CloudProvider(name="test", endpoint="http://test.endpt")
        db_session.add(cp)
        db_session.commit()

    bucket1 = db_session.query(Bucket).filter_by(name="bucket1").first()
    if not bucket1:
        bucket1 = Bucket(name="bucket1", provider_id=cp.id)
        db_session.add(bucket1)
        db_session.commit()

    bucket2 = db_session.query(Bucket).filter_by(name="bucket2").first()
    if not bucket2:
        bucket2 = Bucket(name="bucket2", provider_id=cp.id)
        db_session.add(bucket2)
        db_session.commit()

    project1 = db_session.query(Project).filter_by(name="test_1").first()
    if not project1:
        project1 = Project(name="test_1", auth_id="test_auth_1")
        db_session.add(project1)
        db_session.commit()

    project2 = db_session.query(Project).filter_by(name="test_2").first()
    if not project2:
        project2 = Project(name="test_2", auth_id="test_auth_2")
        db_session.add(project2)
        db_session.commit()

    access_grp1 = (
        db_session.query(GoogleBucketAccessGroup)
        .filter_by(email="test1@gmail.com")
        .first()
    )
    if not access_grp1:
        access_grp1 = GoogleBucketAccessGroup(
            bucket_id=bucket1.id, email="test1@gmail.com"
        )
        db_session.add(access_grp1)
        db_session.commit()

    access_grp2 = (
        db_session.query(GoogleBucketAccessGroup)
        .filter_by(email="test2@gmail.com")
        .first()
    )
    if not access_grp2:
        access_grp2 = GoogleBucketAccessGroup(
            bucket_id=bucket2.id, email="test2@gmail.com"
        )
        db_session.add(access_grp2)
        db_session.commit()

    project_to_bucket1 = (
        db_session.query(ProjectToBucket).filter_by(project_id=project1.id).first()
    )
    if not project_to_bucket1:
        project_to_bucket1 = ProjectToBucket(
            project_id=project1.id, bucket_id=bucket1.id
        )
        db_session.add(project_to_bucket1)
        db_session.commit()

    project_to_bucket2 = (
        db_session.query(ProjectToBucket).filter_by(project_id=project2.id).first()
    )
    if not project_to_bucket2:
        project_to_bucket2 = ProjectToBucket(
            project_id=project2.id, bucket_id=bucket2.id
        )
        db_session.add(project_to_bucket2)
        db_session.commit()

    # new service account each time this is called
    random_string = "".join(
        random.choice(string.ascii_uppercase + string.digits) for _ in range(6)
    )
    user = UserServiceAccount(
        google_unique_id="{}".format(random_string),
        email="{}@test.iam.gserviceaccount.com".format(random_string),
        google_project_id="test",
    )
    db_session.add(user)
    db_session.commit()

    db_session.add(
        ServiceAccountAccessPrivilege(
            project_id=project1.id, service_account_id=user.id
        )
    )
    db_session.add(
        ServiceAccountAccessPrivilege(
            project_id=project2.id, service_account_id=user.id
        )
    )

    # expiration set to 0 for testing that it gets set
    current_time = 0
    service_account_grp1 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=user.id, access_group_id=access_grp1.id, expires=current_time
    )
    service_account_grp2 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=user.id, access_group_id=access_grp2.id, expires=current_time
    )
    db_session.add(service_account_grp1)
    db_session.add(service_account_grp2)
    db_session.commit()

    return {
        "service_account": user,
        "projects": [project1, project2],
        "buckets": [bucket1, bucket2],
        "bucket_access_groups": [access_grp1, access_grp2],
    }


@pytest.fixture(scope="function")
def invalid_service_account_patcher(db_session):
    invalid_service_account = "invalid@example.com"
    user = UserServiceAccount(
        google_unique_id="invalid_test_id",
        email=invalid_service_account,
        google_project_id="test",
    )
    db_session.add(user)
    db_session.commit()

    cp = db_session.query(CloudProvider).filter_by(name="test").first()
    if not cp:
        cp = CloudProvider(name="test", endpoint="http://test.endpt")
        db_session.add(cp)
        db_session.commit()

    bucket1 = db_session.query(Bucket).filter_by(name="bucket1").first()
    if not bucket1:
        bucket1 = Bucket(name="bucket1", provider_id=cp.id)
        db_session.add(bucket1)
        db_session.commit()

    project1 = db_session.query(Project).filter_by(name="test_1").first()
    if not project1:
        project1 = Project(name="test_1", auth_id="test_auth_1")
        db_session.add(project1)
        db_session.commit()

    access_grp1 = (
        db_session.query(GoogleBucketAccessGroup)
        .filter_by(email="test1@gmail.com")
        .first()
    )
    if not access_grp1:
        access_grp1 = GoogleBucketAccessGroup(
            bucket_id=bucket1.id, email="test1@gmail.com"
        )
        db_session.add(access_grp1)
        db_session.commit()

    db_session.add(
        ServiceAccountAccessPrivilege(
            project_id=project1.id, service_account_id=user.id
        )
    )
    db_session.commit()

    # expiration set to 0 for testing that it gets set
    current_time = 0
    service_account_grp1 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=user.id, access_group_id=access_grp1.id, expires=current_time
    )
    db_session.add(service_account_grp1)
    db_session.commit()

    def mock_is_valid(sa_email, *args, **kwargs):
        if sa_email == invalid_service_account:
            validity = GoogleServiceAccountValidity("account_id", "project_id")
            # set overall validity to False
            # set policy_accessible to True so the SA is not removed from the DB
            validity["policy_accessible"] = True
            validity["valid_type"] = False
            return validity
        return True

    patcher = patch(
        "fence.scripting.google_monitor._is_valid_service_account", mock_is_valid
    )

    patcher.start()
    yield {
        "service_account": user,
        "projects": [project1],
        "bucket_access_groups": [access_grp1],
    }
    patcher.stop()


@pytest.fixture(scope="function")
def invalid_service_account_not_exist(db_session):
    invalid_service_account = "invalid@example.com"
    user = UserServiceAccount(
        google_unique_id="invalid_test_id",
        email=invalid_service_account,
        google_project_id="test",
    )
    db_session.add(user)
    db_session.commit()

    cp = db_session.query(CloudProvider).filter_by(name="test").first()
    if not cp:
        cp = CloudProvider(name="test", endpoint="http://test.endpt")
        db_session.add(cp)
        db_session.commit()

    bucket1 = db_session.query(Bucket).filter_by(name="bucket1").first()
    if not bucket1:
        bucket1 = Bucket(name="bucket1", provider_id=cp.id)
        db_session.add(bucket1)
        db_session.commit()

    project1 = db_session.query(Project).filter_by(name="test_1").first()
    if not project1:
        project1 = Project(name="test_1", auth_id="test_auth_1")
        db_session.add(project1)
        db_session.commit()

    access_grp1 = (
        db_session.query(GoogleBucketAccessGroup)
        .filter_by(email="test1@gmail.com")
        .first()
    )
    if not access_grp1:
        access_grp1 = GoogleBucketAccessGroup(
            bucket_id=bucket1.id, email="test1@gmail.com"
        )
        db_session.add(access_grp1)
        db_session.commit()

    db_session.add(
        ServiceAccountAccessPrivilege(
            project_id=project1.id, service_account_id=user.id
        )
    )
    db_session.commit()

    # expiration set to 0 for testing that it gets set
    current_time = 0
    service_account_grp1 = ServiceAccountToGoogleBucketAccessGroup(
        service_account_id=user.id, access_group_id=access_grp1.id, expires=current_time
    )
    db_session.add(service_account_grp1)
    db_session.commit()

    def mock_is_valid(sa_email, *args, **kwargs):
        if sa_email == invalid_service_account:
            validity = GoogleServiceAccountValidity("account_id", "project_id")
            # set overall validity to False
            # set policy_accessible to False so the SA is removed from the DB
            validity["policy_accessible"] = False
            validity._valid = False
            return validity
        return True

    patcher = patch(
        "fence.scripting.google_monitor._is_valid_service_account", mock_is_valid
    )

    patcher.start()
    yield {
        "service_account": user,
        "projects": [project1],
        "bucket_access_groups": [access_grp1],
    }
    patcher.stop()


@pytest.fixture(scope="function")
def user_can_manage_service_account_mock():
    mock = MagicMock()
    mock.return_value = True

    patcher = patch(
        "fence.blueprints.google.is_user_member_of_all_google_projects", mock
    )

    patcher.start()
    yield mock
    patcher.stop()


@pytest.fixture(scope="function")
def valid_user_service_account_mock():
    mock = MagicMock()
    mock.return_value = {"success": True}

    patcher = patch("fence.blueprints.google._get_service_account_error_status", mock)

    patcher.start()
    yield mock
    patcher.stop()


@pytest.fixture(scope="function")
def invalid_user_service_account_mock():
    mock = MagicMock()
    mock.return_value = {"success": False}

    patcher = patch("fence.blueprints.google._get_service_account_error_status", mock)

    patcher.start()
    yield mock
    patcher.stop()


@pytest.fixture(scope="function")
def revoke_user_service_account_from_google_mock():
    mock = MagicMock()

    patcher = patch(
        "fence.resources.google.access_utils._revoke_user_service_account_from_google",
        mock,
    )

    patcher.start()
    yield mock
    patcher.stop()


@pytest.fixture(scope="function")
def add_user_service_account_to_google_mock():
    mock = MagicMock()

    patcher = patch(
        "fence.resources.google.access_utils.add_user_service_account_to_google", mock
    )

    patcher.start()
    yield mock
    patcher.stop()


@pytest.fixture(scope="function")
def test_project(db_session):

    project = Project(id=1, name="test_project", auth_id="test_project")
    db_session.add(project)
    db_session.commit()

    yield project


@pytest.fixture(scope="function")
def test_user(db_session):

    user = User(id=1, email="google_test_user@gmail.com")
    db_session.add(user)
    db_session.commit()

    yield user


@pytest.fixture(scope="function")
def test_linked_user(db_session, test_user):

    user_google_account = UserGoogleAccount(
        id=1, email="google_test_linked_user@gmail.com", user_id=1
    )
    db_session.add(user_google_account)
    db_session.commit()

    yield user_google_account


@pytest.fixture(scope="function")
def test_linked_user_with_access(db_session, test_linked_user, test_project):

    access_privilege = AccessPrivilege(
        user_id=test_linked_user.user_id, project_id=test_project.id
    )
    db_session.add(access_privilege)
    db_session.commit()

    yield test_linked_user
