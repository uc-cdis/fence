import random
import string

import pytest


@pytest.fixture()
def authentication_headers(oidc_client):
    alphanum = string.ascii_letters + string.digits
    state = "".join(random.choice(alphanum) for _ in range(8))
    return {"response_type": "code", "client_id": oidc_client.client_id, "state": state}
