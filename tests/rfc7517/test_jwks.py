from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers


def test_response_fields(client):
    """
    Test for the basic required fields in the response from the JWKs endpoint.

    Fence only uses RSA, so the ``n`` and ``e`` fields for RSA modulus and
    exponent are assumed as well.
    """
    response = client.get('/.well-known/jwks')
    assert response.status_code == 200
    assert 'keys' in response.json
    keys = response.json['keys']
    for key in keys:
        assert 'alg' in key
        assert 'kty' in key
        assert 'use' in key
        assert 'kid' in key
        assert 'n' in key
        assert 'e' in key


def test_response_values(app, client):
    """
    Do some more thorough checking on the response obtained from the JWKS
    endpoint.

    Because fence only uses the RSA algorithm for signing and validating JWTs,
    the ``alg``, ``kty``, ``use``, and ``key_ops`` fields are hard-coded for
    this.

    Furthermore, every JWK in the response should have values for the RSA
    public modulus ``n`` and exponent ``e`` which may be used to reconstruct
    the public key.
    """
    keys = client.get('/.well-known/jwks').json['keys']
    app_kids = [keypair.kid for keypair in app.keypairs]
    app_public_keys = [keypair.public_key for keypair in app.keypairs]
    for key in keys:
        assert key['alg'] == 'RS256'
        assert key['kty'] == 'RSA'
        assert key['use'] == 'sig'
        assert key['key_ops'] == 'verify'
        assert key['kid'] in app_kids
        # Attempt to reproduce the public key from the values for the public
        # modulus and exponent provided in the response, using cryptography
        # primitives.
        n = int(key['n'])
        e = int(key['e'])
        numbers = RSAPublicNumbers(e, n)
        key = numbers.public_key(default_backend())
        key_pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        assert key_pem in app_public_keys
