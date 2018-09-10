import pytest
from fence.models import (
    CloudProvider,
    GoogleBucketAccessGroup,
    ServiceAccountToGoogleBucketAccessGroup,
    GoogleProxyGroup,
    Bucket,
    UserServiceAccount,
    GoogleProxyGroupToGoogleBucketAccessGroup,
)


@pytest.fixture(scope="module")
def example_usernames():
    """Make a list of example usernames."""
    return ["A", "B", "C"]


@pytest.fixture(scope="function", autouse=True)
def patch_driver(db, monkeypatch):
    """
    Change the database driver in ``fence.scripting.fence_create`` to use the
    one from the test fixtures.
    """
    monkeypatch.setattr("fence.scripting.fence_create.SQLAlchemyDriver", lambda _: db)


@pytest.fixture(scope="function")
def setup_test_data(db_session):
    cp = CloudProvider(name="test", endpoint="http://test.endpt")

    proxy_group_list = [
        {"id": "group1", "email": "group1@mail.com"},
        {"id": "group2", "email": "group2@mail.com"},
    ]
    user_account_list = [
        {
            "google_unique_id": "test_id1",
            "email": "user1@gmail.com",
            "google_project_id": "test",
        },
        {
            "google_unique_id": "test_id2",
            "email": "user2@gmail.com",
            "google_project_id": "test",
        },
    ]

    proxy_groups = []
    for group in proxy_group_list:
        proxy_groups.append(GoogleProxyGroup(**group))
        db_session.add(proxy_groups[-1])

    user_service_accounts = []
    for user in user_account_list:
        user_service_accounts.append(UserServiceAccount(**user))
        db_session.add(user_service_accounts[-1])

    db_session.commit()

    bucket1 = Bucket(name="bucket1", provider_id=cp.id)
    bucket2 = Bucket(name="bucket2", provider_id=cp.id)
    bucket3 = Bucket(name="bucket3", provider_id=cp.id)
    db_session.add(bucket1)
    db_session.add(bucket2)
    db_session.add(bucket3)
    db_session.commit()

    access_grp1 = GoogleBucketAccessGroup(
        bucket_id=bucket1.id, email="access_grp_test1@gmail.com"
    )
    db_session.add(access_grp1)
    db_session.commit()

    db_session.add(
        GoogleProxyGroupToGoogleBucketAccessGroup(
            proxy_group_id=proxy_groups[0].id, access_group_id=access_grp1.id
        )
    )

    db_session.add(
        ServiceAccountToGoogleBucketAccessGroup(
            service_account_id=user_service_accounts[0].id,
            access_group_id=access_grp1.id,
        )
    )

    db_session.commit()
