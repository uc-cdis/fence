import json
import mock
import urlparse
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


@pytest.mark.parametrize(
    "indexd_client", ["s3_non_aws"], indirect=True
)
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
    print(indexd_client)
    indexed_file_location = indexd_client["indexed_file_location"]
    print(indexed_file_location)
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
        )
    }
    response = client.get(path, headers=headers, query_string=query_string)
    assert response.status_code == 200
    assert "url" in response.json.keys()

    # defaults to signing url, check that it's not just raw url
    assert urlparse.urlparse(response.json["url"]).query != ""
    print(response.json)
    assert False
