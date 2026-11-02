"""
Bulk DRS signed URL requests must authorize each record the same way the
single-object path does: a record whose `authz` lists several resources requires
read-storage on all of them, not just one.
"""

import mock
import pytest

from fence.blueprints.data.bulk_helpers import process_bulk_signed_urls


OPEN = "/programs/open"
CONTROLLED = "/programs/controlled"
PASSPORT_USER = "passport_user"


class FakeArborist(object):
    """Arborist stand-in whose auth_request requires every resource to be granted."""

    def __init__(self, granted_resources):
        self.granted_resources = set(granted_resources)

    def auth_mapping(self, username=None, jwt=None):
        return {
            resource: [{"service": "fence", "method": "read-storage"}]
            for resource in self.granted_resources
        }

    def auth_request(self, jwt, service, methods, resources, user_id=None):
        return all(resource in self.granted_resources for resource in resources)


class FakeBulk(object):
    """Minimal BulkIndexedFiles stand-in that signs any URL it is asked for."""

    def __init__(self, index_document):
        self.guids = list(index_document)
        self.index_document = index_document
        self.auth_roles = []

    def _get_signed_urls(self, protocol, file_id, *args):
        return f"https://signed.example.com/{file_id}"


def _signed_guids(app, granted_resources, index_document, users_from_passports):
    """Run a bulk request as a caller holding granted_resources; return signed GUIDs."""
    with mock.patch.object(app, "arborist", FakeArborist(granted_resources)):
        with app.test_request_context():
            result = process_bulk_signed_urls(
                FakeBulk(index_document),
                protocol="s3",
                expires_in=3600,
                force_signed_url=True,
                r_pays_project=None,
                users_from_passports=users_from_passports,
                acl_authorization_check=lambda file_id: False,
            )
    return {entry["drs_object_id"] for entry in result.signed_urls}


@pytest.mark.parametrize(
    "users_from_passports",
    [None, {PASSPORT_USER: {}}],
    ids=["bearer", "passport"],
)
def test_multi_resource_record_denied_with_partial_access(app, users_from_passports):
    """A caller holding only one of a record's resources gets no signed URL."""
    index_document = {"guid-both": {"did": "guid-both", "authz": [OPEN, CONTROLLED]}}

    assert _signed_guids(app, {OPEN}, index_document, users_from_passports) == set()


@pytest.mark.parametrize(
    "users_from_passports",
    [None, {PASSPORT_USER: {}}],
    ids=["bearer", "passport"],
)
def test_multi_resource_record_allowed_with_full_access(app, users_from_passports):
    """A caller holding every one of a record's resources gets a signed URL."""
    index_document = {"guid-both": {"did": "guid-both", "authz": [OPEN, CONTROLLED]}}

    assert _signed_guids(
        app, {OPEN, CONTROLLED}, index_document, users_from_passports
    ) == {"guid-both"}


def test_partial_access_only_signs_fully_authorized_records(app):
    """In a mixed batch, only records whose every resource is granted are signed."""
    index_document = {
        "guid-open": {"did": "guid-open", "authz": [OPEN]},
        "guid-both": {"did": "guid-both", "authz": [OPEN, CONTROLLED]},
    }

    assert _signed_guids(app, {OPEN}, index_document, None) == {"guid-open"}
