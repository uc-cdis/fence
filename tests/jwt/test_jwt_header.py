"""
Test parsing the JWT out of the ``Authorization`` header.
"""

import pytest

from fence.errors import Unauthorized
from fence.jwt.utils import get_jwt_header


@pytest.mark.parametrize(
    "authorization",
    ["Bearer some-token", "bearer some-token", "DPoP some-token", "dpop some-token"],
)
def test_supported_scheme_yields_the_token(app, authorization):
    """The token is returned for a `Bearer` or `DPoP` scheme, in any case."""
    with app.test_request_context(headers={"Authorization": authorization}):
        assert get_jwt_header() == "some-token"


@pytest.mark.parametrize(
    "authorization",
    ["bearerXyz some-token", "dpopXyz some-token", "Basic some-token"],
)
def test_unsupported_scheme_is_rejected(app, authorization):
    """A scheme that is not exactly `Bearer` or `DPoP` is rejected."""
    with app.test_request_context(headers={"Authorization": authorization}):
        with pytest.raises(Unauthorized):
            get_jwt_header()
