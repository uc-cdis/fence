# Fence

## Setup

```bash

```

## JWT

Example JWT access token issued by fence:
```
{
    "aud": [
        "user",
        "access"
    ],
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
(Refresh tokens should have just `["refresh"]` for the `aud` field, since a
 refresh token itself is not used for authentication with a service.)

### Keypair Configuration

Generating a keypair using `openssl`:
```bash
# Generate the private key.
openssl rsa -out private_key.pem 2048

# Generate the public key.
openssl rsa -in private_key.pem -pubout -out public_key.pem
```
(It's not a bad idea to confirm that the files actually say `RSA PRIVATE KEY`
and `PUBLIC KEY`.)

Files containing public/private keys should have this format (the format used
by `openssl` for generating RSA keys):
```
-----BEGIN PUBLIC KEY-----
... [key is here] ...
-----END PUBLIC KEY-----
```
If a key is not in this format, then PyJWT will raise errors about not being
able to read the key.

The variable `JWT_KEYPAIR_FILES` in `fence/settings.py` should be set up as an
ordered dictionary mapping key ids to pairs of public and private key files (in
that order); for example:
```
JWT_KEYPAIR_FILES = OrderedDict([
    ('default', ('keys/jwt_public_key.pem', 'keys/jwt_private_key.pem')),
])
```
Fence will use the first keypair in the list to sign the tokens it issues
through OAuth.


## Notes for Development

If a token contains audiences---as the ones issued by fence always
will---`jwt.decode` should always contain an audience, because (as required by
the specification) the validator of any given JWT must identify itself with at
least one of the audiences in the claims of the token. Therefore, all uses of
`jwt.decode` should look like this (where `access` indicates any access token):
```python
token = jwt.decode(
    encoded_token, public_key, algorithm='RS256', audience='refresh'
)
```
