# Fence
> AuthN and AuthZ service

[![Build Status](https://travis-ci.org/uc-cdis/fence.svg?branch=master)](https://travis-ci.org/uc-cdis/fence)
[![Codacy Quality Badge](https://api.codacy.com/project/badge/Grade/1cb2ec9cc64049488d140f44027c4422)](https://www.codacy.com/app/uc-cdis/fence?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=uc-cdis/fence&amp;utm_campaign=Badge_Grade)
[![Codacy Coverage Badge](https://api.codacy.com/project/badge/Coverage/1cb2ec9cc64049488d140f44027c4422)](https://www.codacy.com/app/uc-cdis/fence?utm_source=github.com&utm_medium=referral&utm_content=uc-cdis/fence&utm_campaign=Badge_Coverage)

A `fence` separates protected resources from the outside world and allows
only trusted entities to enter.

Fence is an authentication (AuthN) and authorization (AuthZ) service used
primarily by the Gen3 Data Commons Software Stack.

It utilizes OpenID Connect flow (an extension of OAuth2)
to generate tokens for clients. It can also provide tokens directly
to a user.

Clients and users may then use those tokens with other
Gen3 Data Commons services to access protected endpoints that require specific permissions.

Fence can be configured to support different Identity Providers (IDPs) for AuthN.
At the moment, supported IDPs are:
- Google
- Shibboleth
  - NIH iTrust

## API Documentation

[OpenAPI documentation available here.](http://petstore.swagger.io/?url=https://raw.githubusercontent.com/uc-cdis/fence/master/openapis/swagger.yaml)

YAML file for the OpenAPI documentation is found in the `openapis` folder (in
the root directory); see the README in that folder for more details.

## Setup

#### Install Requirements and Fence

```bash
# Install requirements.
pip install -r requirements.txt
# Install fence in your preferred manner.
python setup.py develop
```

#### Create Local Settings

```bash
# Copy example settings to local settings and then fill them out.
cp fence/local_settings.example.py fence/local_settings.py
```
Remember to fill out `fence/local_settings.py`!

#### Set Up Databases

Because the tests clear out the database every time they are run, if you would
like to keep a persistent database for manual testing and general local usage
simply create a second test database with a different name, as in the
instructions below.

> NOTE: Requires a minimum of Postgres v9.4 (because of `JSONB` types used)

```bash
# Create test database(s).
# This one is for automated tests, which clear the database after running;
# `tests/test_settings.py` should have `fence_test_tmp` in the `DB` variable.
psql -U test postgres -c 'create database fence_test_tmp'
userdatamodel-init --db fence_test_tmp
# This one is for manual testing/general local usage; `fence/local_settings.py`
# should have `fence_test` in the `DB` variable.
psql -U test postgres -c 'create database fence_test'
userdatamodel-init --db fence_test --username test --password test
```

#### Create User Access File
You can setup user access via admin fence script providing a user yaml file
Example user yaml:
```
cloud_providers: {}
groups: {}
users:
  userA@gmail.com:
    projects:
    - auth_id: project_a
      privilege: [read, update, create, delete]
    - auth_id: project_b
      privilege: [read]
  userB@gmail.com:
    projects:
    - auth_id: project_b
      privilege: [read]
```
Example sync command:

```bash
fence-create sync --yaml user.yaml
```

#### Register OAuth Client

Using gdcapi for example:
```bash
fence-create client-create --client gdcapi --urls http://localhost/api/v0/oauth2/authorize --username test
```
That command should output a tuple of `(client_id, client_secret)` which must be
saved so that `gdcapi` (for example) can be run as an OAuth client to use with
`fence`.

#### Modify OAuth Client

Using gdcapi for example:
```bash
fence-create client-modify --client gdcapi --urls http://localhost/api/v0/oauth2/authorize
```
That command should output any modifications to the client.

#### Delete OAuth Client

Using gdcapi for example:
```bash
fence-create client-delete --client gdcapi
```
That command should output the result of the deletion attempt.

#### List OAuth Clients

```bash
fence-create client-list
```
That command should output the full records for any registered OAuth clients.


## Authentication and Authorization

We use JSON Web Tokens (JWTs) as the format for our authentication mechanism.

### JWT Information

#### Example ID Token
```
{
  "sub": "7",
  "azp": "test-client",
  "pur": "id",
  "aud": [
    "openid",
    "user",
    "test-client"
  ],
  "context": {
    "user": {
      "is_admin": false,
      "name": "test",
      "projects": {
        "phs000178": [
          "read",
          "update",
          "create",
          "delete",
          "read-storage"
        ]
      },
      "google": {
          "linked_google_account": "somebody@example.com"
      }
    }
  },
  "iss": "https://bionimbus-pdc.opensciencedatacloud.org",
  "jti": "3ae2910b-0294-43dc-af2a-03fd60082aef",
  "exp": 1516983302,
  "iat": 1516982102,
  "auth_time": 1516982102
}
```

#### Example Access Token
```
{
  "sub": "7",
  "azp": "test-client",
  "pur": "access",
  "aud": [
    "openid",
    "user",
    "test-client"
  ],
  "context": {
    "user": {
      "is_admin": false,
      "name": "test",
      "projects": {
        "phs000178": [
          "read",
          "update",
          "create",
          "delete",
          "read-storage"
        ]
      },
      "google": {
          "proxy_group": "abcdefgh123456",
          "linked_google_account": "somebody@example.com"
      }
    }
  },
  "iss": "https://bionimbus-pdc.opensciencedatacloud.org",
  "jti": "2e6ade06-5afb-4ce7-9ab5-e206225ce291",
  "exp": 1516983302,
  "iat": 1516982102
}
```

#### Example Refresh Token
```
{
  "sub": "7",
  "azp": "test-client",
  "pur": "refresh",
  "aud": [
    "openid",
    "user",
    "test-client"
  ],
  "iss": "https://bionimbus-pdc.opensciencedatacloud.org",
  "jti": "c72e5573-39fa-4391-a445-191e370b7cc5",
  "exp": 1517010902,
  "iat": 1516982102
}
```

### Keypair Configuration

Fence uses RSA keypairs to sign and allow verification of JWTs that it issues.
When the application is initialized, fence loads in keypair files from the
`keys` directory. To store keypair files, use the following procedure:
     - Create a subdirectory in the `fence/keys` directory, named with a
       unique identifier, preferably a timestamp in ISO 8601 format of when
       the keys are created. The name of the directory is used for the `kid`
       (key ID) for those keys; the default (assuming the directory is named
        with an ISO timestamp) looks like this:

           fence_key_2018-05-01T14:00:00Z

     - Generate a private and public keypair following the RSA 256 algorithm
       and store those in that directory. The key files must be named
       `jwt_public_key.pem` and `jwt_private_key.pem`.

To generate a keypair using `openssl`:
```bash
# Generate the private key.
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Generate the public key.
openssl rsa -pubout -in private_key.pem -out public_key.pem

# Depending on the `openssl` distribution, you may find these work instead:
#
#     openssl rsa -out private_key.pem 2048
#     openssl rsa -in private_key.pem -pubout -out public_key.pem
```
It's not a bad idea to confirm that the files actually say `RSA PRIVATE KEY`
and `PUBLIC KEY` (and in fact fence will require that the private key files it
uses actually say "PRIVATE KEY" and that the public keys do not).

Files containing public/private keys should have this format (the format used
by `openssl` for generating RSA keys):
```
-----BEGIN PUBLIC KEY-----
... [key is here] ...
-----END PUBLIC KEY-----
```
If a key is not in this format, then `PyJWT` will raise errors about not being
able to read the key.

Fence will use the first keypair in the list to sign the tokens it issues
through OAuth.

## OIDC & OAuth2

Fence acts as a central broker that supports multiple Identity Providers (IDPs).
It exposes AuthN and AuthZ for users by acting as an OIDC IDP itself.
In that sense, `fence` is both a `client` and `OpenID Provider (OP)`.

### Fence as Client

Example:

- Google IAM is the OpenID Provider (OP)
- Fence is the client
- Google Calendar API is the resource provider

### Fence as OpenID Provider (OP)

- Fence is the OP
- A third-party application is the client
- Our microservices (e.g. [`sheepdog`](https://github.com/uc-cdis/sheepdog)) are resource providers

### Example Flows

Note that the `3rd Party App` acts as the `client` in these examples.

[//]: # (See /docs folder for README on how to regenerate these sequence diagrams)

#### Flow: Client Registration

![Client Registration](docs/client_registration.png)

#### Flow: OpenID Connect

![OIDC Flow](docs/openid_connect_flow.png)

If the third-party application doesn't need to use any Gen3 resources (and just
wants to authenticate the user), after the handshake is finished they can just get
needed information in the `ID token`.

#### Flow: Using Tokens for Access

If a third-party application want to use Gen3 resources like
`fence`/`sheepdog`/`peregrine`, they call those services with an `Access Token`
passed in an `Authorization` header.

![Using Access Token](docs/token_use_for_access.png)

#### Flow: Refresh Token Use

![Using Refresh Token](docs/refresh_token_use.png)

#### Flow: Refresh Token Use (Token is Expired)

![Using Expired Refresh Token](docs/refresh_token_use_expired.png)

#### Flow: Multi-Tenant Fence

The following diagram illustrates the case in which one fence instance should
use another fence instance as its identity provider.

![Multi-Tenant Flow](docs/multi-tenant_flow.png)

#### Notes

See the [OIDC specification](http://openid.net/specs/openid-connect-core-1_0.html) for more details.
Additionally, see the [OAuth2 specification](https://tools.ietf.org/html/rfc6749).

## Accessing Data

Fence has multiple options that provide a mechanism to access data. The access
to data can be moderated through authorization information in a User Access File.

Users can be provided specific `privilege`'s on `projects` in the User Access
File. A `project` is identified by a unique authorization identifier AKA `auth_id`.

A `project` can be associated with various storage backends that store
data for that given `project`. You can assign `read-storage` and `write-storage`
privilieges to users who should have access to that stored data.

Depending on the backend, Fence can be configured to provide users access to
the data in different ways.

### Google Cloud Storage

There are various mechanisms for end-users to access data stored within
Google Cloud Storage. They require some extra configuration and setup to
function correctly.

#### Signed URLS

Ability to request a specific file by its UUID and retrieve a temporary
signed URL that will provide direct access to that file.

#### Temporary Credentials

Obtain Google Service Account credentials that will have the same access
a user does to data. One can then use these credentials to AuthN as that
service account and manipulate the data within Google's Cloud Platform.

Note that these provided credentials are temporary and will expire after some
time. You will need to request new ones regularly.

#### Google Account Linking

Allows end-users to link a Google Account to their normal Fence User account.
This will provide temporary data access to that Google account. The Google account
will have the same access the user has.

NOTE: The data access is temporary, though there is a Fence endpoint to
extend access (without requiring the end-user to go through the entire
linking process again).

#### Service Account Registration

This allows an end-user to create their own personal Google Cloud Project
and register a Google Service Account from that project to have access
to data. While this method allows the most flexibility, it is also the
most complicated and requires strict adherence to a number of rules and
restrictions.

This method also requires Fence to have access to that
end-user's Google project. Fence is then able to monitor the project
for any anomolies that may unintentionally provide data access to entities
who should not have access.

