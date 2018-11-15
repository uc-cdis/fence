from collections import OrderedDict

from fence.jwt.keys import load_keypairs


def test_reconstruct_keys_dict(app, client):
    """
    Test reconstructing the dictionary mapping key ids to public keys from the
    return value from the public keys endpoint.
    """
    response = client.get("/jwt/keys")
    public_keys_dict = OrderedDict(response.json["keys"])
    assert public_keys_dict == app.jwt_public_keys[app.config["BASE_URL"]]
