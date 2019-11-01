from fence.models import (
    Client,
    GoogleBucketAccessGroup,
    ServiceAccountAccessPrivilege,
    ServiceAccountToGoogleBucketAccessGroup,
    User,
    UserServiceAccount,
)
from userdatamodel.user import Bucket, Project
from fence.utils import random_str


def test_user_delete_cascade(db_session):
    """
    test deleting a user will cascade to its children
    """
    user = User(username="test_user")
    client = Client(
        name="test_client",
        user=user,
        client_id=random_str(40),
        client_secret=random_str(60),
    )
    db_session.add(user)
    db_session.add(client)
    db_session.flush()
    assert len(user.clients) == 1
    db_session.delete(user)
    assert db_session.query(Client).filter_by(client_id=client.client_id).count() == 0


def test_service_account_relationships(db_session):
    """
    test service account tables have proper relationships/fields
    """
    project = Project(id=1)
    bucket = Bucket(id=1)
    user_sa = UserServiceAccount(
        id=1,
        google_unique_id="guid",
        email="email@google.com",
        google_project_id="gpid",
    )
    sa_access_privilege = ServiceAccountAccessPrivilege(
        id=1, project_id=1, service_account_id=1
    )
    gbag = GoogleBucketAccessGroup(id=1, bucket_id=1, email="email@google.com")
    sa_to_gbag = ServiceAccountToGoogleBucketAccessGroup(
        id=1, service_account_id=1, expires=0, access_group_id=1
    )
    db_session.add(project)
    db_session.add(bucket)
    db_session.add(user_sa)
    db_session.add(sa_access_privilege)
    db_session.add(gbag)
    db_session.add(sa_to_gbag)
    db_session.commit()
    assert project.sa_access_privileges[0].__class__ == ServiceAccountAccessPrivilege
    assert project.sa_access_privileges[0].id == 1
    assert sa_access_privilege.project.__class__ == Project
    assert sa_access_privilege.project.id == 1
    assert sa_access_privilege.service_account.__class__ == UserServiceAccount
    assert sa_access_privilege.service_account.id == 1
    assert user_sa.access_privileges[0].__class__ == ServiceAccountAccessPrivilege
    assert user_sa.access_privileges[0].id == 1
    assert (
        user_sa.to_access_groups[0].__class__ == ServiceAccountToGoogleBucketAccessGroup
    )
    assert user_sa.to_access_groups[0].id == 1
    assert sa_to_gbag.service_account.__class__ == UserServiceAccount
    assert sa_to_gbag.service_account.id == 1
    assert sa_to_gbag.access_group.__class__ == GoogleBucketAccessGroup
    assert sa_to_gbag.access_group.id == 1
    assert gbag.to_access_groups[0].__class__ == ServiceAccountToGoogleBucketAccessGroup
    assert gbag.to_access_groups[0].id == 1
