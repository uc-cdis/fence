# Fence

[![Build Status](https://travis-ci.org/uc-cdis/fence.svg?branch=master)](https://travis-ci.org/uc-cdis/fence)
[![Codacy Quality Badge](https://api.codacy.com/project/badge/Grade/1cb2ec9cc64049488d140f44027c4422)](https://www.codacy.com/app/uc-cdis/fence?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=uc-cdis/fence&amp;utm_campaign=Badge_Grade)
[![Codacy Coverage Badge](https://api.codacy.com/project/badge/Coverage/1cb2ec9cc64049488d140f44027c4422)](https://www.codacy.com/app/uc-cdis/fence?utm_source=github.com&utm_medium=referral&utm_content=uc-cdis/fence&utm_campaign=Badge_Coverage)

## Setup for development

```bash
# install postgres
# Depending on how you have postgres setup, you may need to change the configuration in pb_hba.conf to allow those users to connect without password (trust instead of md5)
# Create role test and add the same permissions that postgres have

# Install requirements.
pip install -r dev-requirements.txt
# Install fence in your preferred manner.
python setup.py develop
# Create test database.
# Also user test may need to be created
psql -U test postgres -c 'create database fence_test'
# Initialize models in test database.
# You need a local_settings.py file in that directory. If you want to use the example one, on fence/, remove 'example' from the name,
# and modify DB's value to '[...]/fence_test'
userdatamodel-init --db fence_test
# Populate the database with your basic UA file.
fence-create --path fence create ua.yaml
# Register OAuth client (example).
fence-create --path fence client-create --client gdcapi --urls http://localhost/api/v0/oauth2/authorize --username test
# That command should output: (client_id, client_secret) which must be saved so
# that gdcapi (for example) can be run as an OAuth client to use with fence.
```

## API Documentation

[OpenAPI documentation available here.](http://petstore.swagger.io/?url=https://raw.githubusercontent.com/uc-cdis/fence/master/openapi/swagger.yaml)

YAML file for the OpenAPI documentation is found in the `openapi` folder (in
the root directory); see the README in that folder for more details.

## JWT

Example JWT access token issued by fence:
```
{
    "aud": [
        "user",
        "access"
    ],
    "iat": 1510854627,
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
    }
}
```
(Refresh tokens should have just `["refresh"]` for the `aud` field, since a
 refresh token itself is not used for authentication with a service.)

### Keypair Configuration

Generating a keypair using `openssl`:
```bash
# Generate the private key.
openssl genrsa -out private_key.pem 2048

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

## OAuth2

See the [OAuth2 specification](https://tools.ietf.org/html/rfc6749) for details.

This implementation diverges slightly from the recommendations (but not
requirements!) of the specification, primarily where flask-oauthlib diverges.

- https://github.com/lepture/flask-oauthlib/issues/184

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
