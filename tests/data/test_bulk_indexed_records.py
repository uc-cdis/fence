"""
Test suite for the Bulk Content Retrieval support
"""

from unittest.mock import MagicMock

import pytest
from requests import JSONDecodeError

from fence.config import config
from fence.blueprints.data.indexd import BulkIndexedRecords
from fence.errors import NotFound, NotSupported, UnavailableError


@pytest.fixture
def guid_list() -> list[str]:
    """Return a list of dummy GUIDs used in the tests"""
    return ["guid-1", "guid-2", "guid-3"]


@pytest.fixture
def mock_embeddings_config(monkeypatch):
    """Set up mock configuration for Gen3 Embeddings"""
    import fence.blueprints.data.indexd as indexd_module

    monkeypatch.setitem(
        indexd_module.config,
        "ALLOWED_GEN3_EMBEDDINGS_BULK_URL_PREFIXES",
        ["https://example.com/ai"],
    )
    monkeypatch.setitem(
        indexd_module.config,
        "GEN3_EMBEDDINGS_API_REGEX",
        "/collections/(?P<collection_name>[\w-]+)/embeddings/(?P<embedding_uuid>[\w-]+)",
    )


def test_bulk_indexed_records_successful(guid_list, monkeypatch):
    """Verify a successful bulk call returns a mapping of GUIDs to records"""
    expected_records = [{"did": guid, "foo": f"bar-{guid}"} for guid in guid_list]

    monkeypatch.setattr(
        "fence.blueprints.data.indexd.requests.post",
        lambda url, data: _mock_response(200, expected_records),
    )
    import fence.blueprints.data.indexd as indexd_module

    monkeypatch.setitem(indexd_module.config, "INDEXD", "http://example.com")

    bulk_records = BulkIndexedRecords(guid_list)

    assert isinstance(bulk_records.bulk_indexed_records, dict)
    assert set(bulk_records.bulk_indexed_records.keys()) == set(guid_list)
    for guid in guid_list:
        assert bulk_records.bulk_indexed_records[guid] == {
            "did": guid,
            "foo": f"bar-{guid}",
        }


def test_bulk_indexed_records_non_json(guid_list, monkeypatch):
    """A response that cannot be parsed as JSON should raise InternalError"""
    monkeypatch.setattr(
        "fence.blueprints.data.indexd.requests.post",
        lambda url, data: _mock_response(200, raise_json_error=True),
    )
    import fence.blueprints.data.indexd as indexd_module

    monkeypatch.setitem(indexd_module.config, "INDEXD", "http://example.com")

    bulk_records = BulkIndexedRecords(guid_list)
    with pytest.raises(Exception):
        bulk_records.bulk_indexed_records


def test_bulk_indexed_records_400(guid_list, monkeypatch):
    """A 400 status from indexd translates to NotFound"""
    monkeypatch.setattr(
        "fence.blueprints.data.indexd.requests.post",
        lambda url, data: _mock_response(400),
    )
    import fence.blueprints.data.indexd as indexd_module

    monkeypatch.setitem(indexd_module.config, "INDEXD", "http://example.com")

    bulk_records = BulkIndexedRecords(guid_list)
    with pytest.raises(NotFound):
        bulk_records.bulk_indexed_records


def test_bulk_indexed_records_unavailable(guid_list, monkeypatch):
    """Any status other than 200 or 400 raises UnavailableError"""
    monkeypatch.setattr(
        "fence.blueprints.data.indexd.requests.post",
        lambda url, data: _mock_response(503),
    )
    import fence.blueprints.data.indexd as indexd_module

    monkeypatch.setitem(indexd_module.config, "INDEXD", "http://example.com")

    bulk_records = BulkIndexedRecords(guid_list)
    with pytest.raises(UnavailableError):
        bulk_records.bulk_indexed_records


def test_get_bulk_requests_and_mapping_success(mock_embeddings_config):
    """Verify successful parsing and mapping of a single valid GUID record"""
    bulk_records = BulkIndexedRecords(["guid-1"])

    # bypass indexd network call by mocking the cached_property's internal dict cache
    bulk_records.__dict__["bulk_indexed_records"] = {
        "guid-1": {
            "urls": [
                "https://example.com/ai/collections/collection-A/embeddings/uuid-123"
            ]
        }
    }

    urls_and_payloads, id_to_guid = bulk_records.get_bulk_requests_and_mapping()

    assert urls_and_payloads == {
        "https://example.com/ai/vectorstore/collections/collection-A/embeddings/bulk": [
            "uuid-123"
        ]
    }
    assert id_to_guid == {"uuid-123": "guid-1"}


def test_get_bulk_requests_and_mapping_multiple_records(mock_embeddings_config):
    """Verify multiple IDs under the same collection group correctly together"""
    bulk_records = BulkIndexedRecords(["guid-1", "guid-2"])
    bulk_records.__dict__["bulk_indexed_records"] = {
        "guid-1": {
            "urls": [
                "https://example.com/ai/collections/collection-A/embeddings/uuid-1"
            ]
        },
        "guid-2": {
            "urls": [
                "https://example.com/ai/collections/collection-A/embeddings/uuid-2"
            ]
        },
    }

    urls_and_payloads, id_to_guid = bulk_records.get_bulk_requests_and_mapping()

    # both payloads should aggregate into the list under the matching collection endpoint
    assert urls_and_payloads == {
        "https://example.com/ai/vectorstore/collections/collection-A/embeddings/bulk": [
            "uuid-1",
            "uuid-2",
        ]
    }
    assert id_to_guid == {"uuid-1": "guid-1", "uuid-2": "guid-2"}


def test_get_bulk_requests_and_mapping_invalid_prefix(mock_embeddings_config):
    """
    An unallowed URL prefix should immediately trigger NotSupported, even if a valid one is
    also present
    """
    bulk_records = BulkIndexedRecords(["guid-1", "guid-2"])
    bulk_records.__dict__["bulk_indexed_records"] = {
        "guid-1": {
            "urls": [
                "https://example.com/ai/collections/collection-A/embeddings/uuid-1"
            ]
        },
        "guid-2": {
            "urls": ["s3://forbidden-bucket/collections/collection-A/embeddings/uuid-1"]
        },
    }

    with pytest.raises(NotSupported):
        bulk_records.get_bulk_requests_and_mapping()


def test_get_bulk_requests_and_mapping_regex_mismatch(
    monkeypatch, mock_embeddings_config
):
    """A valid prefix but malformed API path (regex mismatch) triggers NotSupported"""

    def mock_bad_path_from_url(url):
        mock_loc = MagicMock()
        mock_loc.url = url
        mock_loc.parsed_url.path = "/malformed/path/structure/here"
        return mock_loc

    monkeypatch.setattr(
        "fence.blueprints.data.indexd.IndexedFileLocation.from_url",
        mock_bad_path_from_url,
    )

    bulk_records = BulkIndexedRecords(["guid-1"])
    bulk_records.__dict__["bulk_indexed_records"] = {
        "guid-1": {"urls": ["https://example.com/ai/malformed/path/structure/here"]}
    }

    with pytest.raises(NotSupported):
        bulk_records.get_bulk_requests_and_mapping()


def test_get_bulk_requests_and_mapping_empty_urls(mock_embeddings_config):
    """Records containing zero URLs should raise NotSupported"""
    bulk_records = BulkIndexedRecords(["guid-1"])
    bulk_records.__dict__["bulk_indexed_records"] = {"guid-1": {"urls": []}}

    with pytest.raises(NotSupported):
        bulk_records.get_bulk_requests_and_mapping()


def test_get_bulk_content_exceeds_max_guids(
    client, monkeypatch, mock_embeddings_config
):
    """If request has too many GUIDs (beyond configured max), should error"""
    guids = ["guid-1", "guid-2"]
    bulk_records = BulkIndexedRecords(guids)
    bulk_records.__dict__["bulk_indexed_records"] = {
        "guid-1": {
            "urls": [
                "https://example.com/ai/collections/collection-A/embeddings/uuid-1"
            ]
        },
        "guid-2": {
            "urls": [
                "https://example.com/ai/collections/collection-A/embeddings/uuid-2"
            ]
        },
    }
    data = {"guids": guids}

    monkeypatch.setitem(config, "MAX_BULK_CONTENT_GUIDS_COUNT", 1)
    response = client.post("/data/content", json=data)
    assert response.status_code == 413


def test_get_bulk_content_success(client, monkeypatch, mock_embeddings_config):
    """Verify a successful bulk content retrieval return structured mapping"""
    mock_bulk_instance = MagicMock()
    mock_bulk_instance.bulk_indexed_records = {
        "guid-1": {
            "urls": [
                "https://example.com/ai/collections/collection-A/embeddings/uuid-123"
            ],
        },
    }
    mock_bulk_instance.get_bulk_requests_and_mapping.return_value = (
        [
            (
                "https://example.com/ai/collections/collection-A/embeddings/bulk",
                ["uuid-123"],
            )
        ],
        {"uuid-123": "guid-1"},
    )

    monkeypatch.setattr(
        "fence.blueprints.data.indexd.BulkIndexedRecords",
        MagicMock(return_value=mock_bulk_instance),
    )

    def post(url, *args, **kwargs):
        # Gen3 AI Embeddings Bulk Service
        if "embeddings/bulk" in url:
            mock_ai_resp = MagicMock()
            mock_ai_resp.status_code = 200
            mock_ai_resp.json.return_value = {
                "embeddings": [
                    {"embedding_id": uuid, "vector": [0.1, 0.2, 0.3]}
                    for uuid in kwargs.get("data", [])
                ]
            }
            return mock_ai_resp

        # indexd bulk documents resolution
        if "/bulk/documents" in url:
            mock_indexd_resp = MagicMock()
            mock_indexd_resp.status_code = 200
            mock_indexd_resp.json.return_value = [
                {
                    "did": "guid-1",
                    "urls": [
                        "https://example.com/ai/collections/collection-A/embeddings/uuid-123"
                    ],
                }
            ]
            return mock_indexd_resp

        # fallback for other framework POST requests
        fallback_resp = MagicMock()
        fallback_resp.status_code = 200
        fallback_resp.json.return_value = {}
        return fallback_resp

    monkeypatch.setattr("fence.blueprints.data.indexd.requests.post", post)

    data = {"guids": ["guid-1"]}
    response = client.post("/data/content", json=data)

    assert response.status_code == 200

    json_data = response.get_json()
    assert json_data["total_guids"] == 1
    assert "guids" in json_data
    assert "guid-1" in json_data.get("guids", {})
    assert json_data["guids"]["guid-1"].get("embedding_id") == "uuid-123"


def test_get_bulk_content_unallowed_url(client, monkeypatch, mock_embeddings_config):
    """If the bulk URL returned doesn't match allowlisted prefixes, return UserError"""
    mock_bulk_instance = MagicMock()
    # provide a rogue/forbidden URL structure
    mock_bulk_instance.get_bulk_requests_and_mapping.return_value = (
        [("https://forbidden-domain.com/bulk", ["uuid-123"])],
        {"uuid-123": "guid-1"},
    )

    monkeypatch.setattr(
        "fence.blueprints.data.indexd.BulkIndexedRecords",
        MagicMock(return_value=mock_bulk_instance),
    )

    data = {"guids": ["guid-1"]}

    response = client.post("/data/content", json=data)
    assert response.status_code != 200


def _mock_response(status_code: int, data=None, raise_json_error: bool = False):
    """Return a mock requests response object"""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    if raise_json_error:
        mock_resp.json.side_effect = JSONDecodeError("not json")
    else:
        mock_resp.json.return_value = data
    return mock_resp
