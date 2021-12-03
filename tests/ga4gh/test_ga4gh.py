import time
import jwt

from cdislogging import get_logger

from fence.config import config
from fence.models import IdentityProvider, IssSubPairToUser
from fence.resources.openid.ras_oauth2 import RASOauth2Client
from fence.resources.ga4gh.passports import get_or_create_gen3_user_from_iss_sub

logger = get_logger(__name__, log_level="debug")


def test_get_or_create_gen3_user_from_iss_sub_without_prior_login(
    db_session, mock_arborist_requests
):
    """
    Test get_or_create_gen3_user_from_iss_sub when the visa's <iss, sub>
    combination are not present in the mapping table beforehand (i.e. the user
    has not previously logged in)
    """
    mock_arborist_requests({"arborist/user/": {"PATCH": (None, 204)}})

    iss = "https://stsstg.nih.gov"
    sub = "123_abc"

    user = get_or_create_gen3_user_from_iss_sub(iss, sub, db_session=db_session)

    assert user.username == "123_abcstsstg.nih.gov"
    assert user.identity_provider.name == IdentityProvider.ras
    iss_sub_pair_to_user_records = db_session.query(IssSubPairToUser).all()
    assert len(iss_sub_pair_to_user_records) == 1
    assert iss_sub_pair_to_user_records[0].user.username == "123_abcstsstg.nih.gov"


def test_get_or_create_gen3_user_from_iss_sub_after_prior_login(
    db_session, mock_arborist_requests
):
    """
    Test get_or_create_gen3_user_from_iss_sub when the visa's <iss, sub>
    combination are present in the mapping table beforehand (i.e. the user
    has previously logged in)
    """
    mock_arborist_requests({"arborist/user/": {"PATCH": (None, 204)}})

    iss = "https://stsstg.nih.gov"
    sub = "123_abc"
    username = "johnsmith"
    email = "johnsmith@domain.tld"
    oidc = config["OPENID_CONNECT"]
    ras_client = RASOauth2Client(
        oidc["ras"],
        HTTP_PROXY=config["HTTP_PROXY"],
        logger=logger,
    )
    ras_client.map_iss_sub_pair_to_user(iss, sub, username, email)
    iss_sub_pair_to_user_records = db_session.query(IssSubPairToUser).all()
    assert len(iss_sub_pair_to_user_records) == 1
    assert iss_sub_pair_to_user_records[0].user.username == username

    user = get_or_create_gen3_user_from_iss_sub(iss, sub, db_session=db_session)

    iss_sub_pair_to_user_records = db_session.query(IssSubPairToUser).all()
    assert len(iss_sub_pair_to_user_records) == 1
    assert iss_sub_pair_to_user_records[0].user.username == username
    assert user.username == username
    assert user.email == email
