"""
Unit tests for fence/blueprints/data/bulk_helpers.py.
"""

import pytest

from fence.blueprints.data.bulk_helpers import (
    _auth_mapping_has_read_storage,
    collect_authz_needing_check,
    normalize_authz_key,
)


@pytest.mark.parametrize(
    "method_entry,expected",
    [
        ({"service": "fence", "method": "read-storage"}, True),  # exact match
        ({"service": "*", "method": "read-storage"}, True),  # wildcard service
        ({"service": "fence", "method": "*"}, True),  # wildcard method
        ({"service": "*", "method": "*"}, True),  # wildcard service + method
        ({"service": "fence", "method": "write-storage"}, False),  # unrelated method
    ],
)
def test_auth_mapping_has_read_storage(method_entry, expected):
    """
    A single auth_mapping entry should grant read-storage via exact or wildcard match.
    """
    auth_mapping = {"/programs/test": [method_entry]}
    assert _auth_mapping_has_read_storage(auth_mapping, "/programs/test") is expected


@pytest.mark.parametrize(
    "file_authz,expected",
    [
        (["b", "a"], ("a", "b")),  # list -> sorted tuple
        ("/programs/test", "/programs/test"),  # str -> unchanged
        (None, None),  # unexpected type -> None
    ],
)
def test_normalize_authz_key(file_authz, expected):
    """
    authz values should normalize to a sorted tuple, an unchanged string, or None.
    """
    assert normalize_authz_key(file_authz) == expected


def test_collect_authz_needing_check():
    """
    Only files with a new (not already-authorized) authz key are collected.
    """
    index_document = {
        "guid-1": {"authz": "/programs/a"},  # needs check
        "guid-2": {"authz": "/programs/b"},  # already authorized
        "guid-3": {},  # no authz
    }
    result = collect_authz_needing_check(
        guids=["guid-1", "guid-2", "guid-3", "missing-guid"],
        index_document=index_document,
        auth_roles=["/programs/b"],
    )
    assert result == {"/programs/a"}
