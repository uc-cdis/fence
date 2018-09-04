import fence.resources.admin as adm
from fence.models import CloudProvider
from fence.errors import UserError, NotFound
import pytest


def test_get_provider(db_session, providers):
    info = adm.get_provider(db_session, "provider_a")
    assert info["name"] == "provider_a"
    assert info["backend"] == "cleversafe"
    assert info["service"] == "storage"


def test_get_inexistent_provider(db_session, providers):
    with pytest.raises(NotFound):
        info = adm.get_provider(db_session, "provider_c")


def test_create_provider(db_session, providers):
    provider = db_session.query(CloudProvider).filter_by(name="provider_c").first()
    assert provider == None
    adm.create_provider(db_session, "provider_c", "cleversafe", "storage")
    info = db_session.query(CloudProvider).filter_by(name="provider_c").first()
    assert info.name == "provider_c"
    assert info.backend == "cleversafe"
    assert info.service == "storage"


def test_create_provider_that_already_exists(db_session, providers):
    provider = db_session.query(CloudProvider).filter_by(name="provider_a").first()
    assert provider != None
    with pytest.raises(UserError):
        adm.create_provider(db_session, "provider_a", "cleversafe", "storage")


def test_delete_provider(db_session, providers):
    provider = db_session.query(CloudProvider).filter_by(name="provider_a").first()
    assert provider.name == "provider_a"
    adm.delete_provider(db_session, "provider_a")
    provider = db_session.query(CloudProvider).filter_by(name="provider_a").first()
    assert provider == None


def test_delete_inexistentprovider(db_session, providers):
    provider = db_session.query(CloudProvider).filter_by(name="provider_c").first()
    assert provider == None
    with pytest.raises(NotFound):
        adm.delete_provider(db_session, "provider_c")
