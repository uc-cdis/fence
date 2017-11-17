# Fence

## JWT

Example JWT issued by fence:
```
{
    "exp": 1510858227,
    "sub": "25",
    "iss": "http://api.bloodpac-data.org",
    "jti": "d132f979-6cba-4382-abe7-426d6d52bcfa",
    "context": {
        "user": {
            "name": "test",
            "projects": {
                "testproject": [
                    "read",
                    "update",
                    "create",
                    "delete"
                ],
            }
        }
    },
    "iat": 1510854627
}
```

### Keypair Configuration

Files containing public/private keys should have the following format (the
format used by `openssl` for generating RSA keys):
```
-----BEGIN PUBLIC KEY-----
... [key is here] ...
-----END PUBLIC KEY-----
```

The variable `JWT_KEYPAIR_FILES` in `fence/settings.py` should then be set up
as an ordered dictionary mapping key ids to pairs of public and private key
files (in that order); for example:
```
JWT_KEYPAIR_FILES = OrderedDict([
    ('default', ('keys/jwt_public_key.pem', 'keys/jwt_private_key.pem')),
])
```

Fence will use the first keypair in the list to sign the tokens it issues
through OAuth.
