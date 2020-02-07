import json
import mock
from urllib import parse
import uuid

import jwt
import pytest
import requests

import fence.blueprints.data.indexd
from fence.config import config
from fence.errors import NotSupported

from tests import utils

# Python 2 and 3 compatible
try:
    from unittest.mock import MagicMock
    from unittest.mock import patch
except ImportError:
    from mock import MagicMock
    from mock import patch


def test_indexd_download_file(
    client,
    oauth_client,
    user_client,
    indexd_client,
    kid,
    rsa_private_key,
    google_proxy_group,
    primary_google_service_account,
    cloud_manager,
    google_signed_url,
):
    """
    Test ``GET /data/download/1``.
    """

    index_document = {
        "did": "",
        "baseid": "",
        "rev": "",
        "size": 10,
        "file_name": "file1",
        "urls": ["s3://bucket6/key"],
        "hashes": {},
        "acl": ["phs000178", "phs000218"],
        "form": "",
        "created_date": "",
        "updated_date": "",
    }
    mock_index_document = mock.patch(
        "fence.blueprints.data.indexd.IndexedFile.index_document", index_document
    )
    mock_index_document.start()

    indexed_file_location = indexd_client["indexed_file_location"]
    path = "/data/download/1"
    query_string = {"protocol": indexed_file_location}
    headers = {
        "Authorization": "Bearer "
        + jwt.encode(
            utils.authorized_download_context_claims(
                user_client.username, user_client.user_id
            ),
            key=rsa_private_key,
            headers={"kid": kid},
            algorithm="RS256",
        ).decode("utf-8")
    }
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 200
    assert "url" in response.json.keys()

    # defaults to signing url, check that it's not just raw url
    assert parse.urlparse(response.json["url"]).query != ""
    assert 's3.amazonaws.com' not in response.json['url'], "Shouldn't have an aws url"

    mock_index_document.stop()
