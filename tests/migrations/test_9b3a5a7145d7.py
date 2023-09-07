"""
"Non-unique client name" migration
"""

from alembic.config import main as alembic_main
import pytest
from sqlalchemy.exc import IntegrityError

from fence.models import Client
from fence.utils import random_str
import bcrypt


@pytest.fixture(scope="function", autouse=True)
def post_test_clean_up(app):
    yield

    # clean up the client table
    with app.db.session as db_session:
        db_session.query(Client).delete()

    # go back to the latest state of the DB
    alembic_main(["--raiseerr", "upgrade", "head"])


def test_upgrade(app):
    client_name = "client_name"
    url = "https://oauth-client.net"
    client_id = "test-client"
    client_secret = random_str(50)
    hashed_secret = bcrypt.hashpw(
        client_secret.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")
    grant_types = ["refresh_token"]
    allowed_scopes = ["openid", "user", "fence"]
    with app.db.session as db_session:
        db_session.add(
            Client(
                client_id=client_id,
                client_secret=hashed_secret,
                allowed_scopes=allowed_scopes,
                redirect_uris=[url],
                description="",
                is_confidential=True,
                name=client_name,
                grant_types=grant_types,
            )
        )
        db_session.commit()
        query_result = db_session.query(Client).all()

    # make sure the client was created and the new _client_metadata field is populated and Authlib getters are working
    assert len(query_result) == 1, query_result
    assert query_result[0].name == client_name
    assert query_result[0].client_secret == hashed_secret
    assert query_result[0].scope == " ".join(allowed_scopes)
    assert query_result[0].grant_types == grant_types
    assert query_result[0].redirect_uris == [url]
