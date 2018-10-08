# Fence

[![Build Status](https://travis-ci.org/uc-cdis/fence.svg?branch=master)](https://travis-ci.org/uc-cdis/fence)
[![Codacy Quality Badge](https://api.codacy.com/project/badge/Grade/1cb2ec9cc64049488d140f44027c4422)](https://www.codacy.com/app/uc-cdis/fence?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=uc-cdis/fence&amp;utm_campaign=Badge_Grade)
[![Codacy Coverage Badge](https://api.codacy.com/project/badge/Coverage/1cb2ec9cc64049488d140f44027c4422)](https://www.codacy.com/app/uc-cdis/fence?utm_source=github.com&utm_medium=referral&utm_content=uc-cdis/fence&utm_campaign=Badge_Coverage)

A `fence` separates protected resources from the outside world and allows
only trusted entities to enter.

Fence is a core service of the Gen3 stack that has multiple capabilities:
1. Act as an auth broker to integrate with an [Identity Provider](#identity-provider) and provide downstream authentication and authorization for Gen3 services.
2. [Manage tokens](#token-management).
3. Act as an [OIDC provider](oidc--oauth2) to support external applications to use Gen3 services.
4. [Issue short lived, cloud native credentials to access data in various cloud storage services](#accessing-data)


## API Documentation

[OpenAPI documentation available here.](http://petstore.swagger.io/?url=https://raw.githubusercontent.com/uc-cdis/fence/master/openapis/swagger.yaml)

YAML file for the OpenAPI documentation is found in the `openapis` folder (in
the root directory); see the README in that folder for more details.

## Terminologies


#### AuthN
Authentication - establishes "who you are" with the application through communication with an [Identity Provider](#IdP).

#### AuthZ
Authorization - establishes "what you can do" and "which resources you have access to" within the application.

#### IdP
Identity Provider - the service that lets a user login and provides the identity of the user to downstream services. Example: Google login, University login, NIH Login.

#### OAuth2
A widely used protocol for delegating access to an application to use resources on behalf of a user.

https://tools.ietf.org/html/rfc6749

https://oauth.net/2/

#### OIDC
OpenID Connect - an extention of OAuth2 which provides more detailed specification about the handshake. It introduced a new type of token, the id token, that is specifically designed to be consumed by clients to get the identity information of the user.

http://openid.net/specs/openid-connect-core-1_0.html


## Identity Provider
Fence can be configured to support different Identity Providers (IdPs) for AuthN.
At the moment, supported IDPs include:
- Google
- Shibboleth
  - NIH iTrust
  - InCommon
  - eduGAIN


## OIDC & OAuth2

Fence acts as a central broker that supports multiple Identity Providers (IdPs).
It exposes AuthN and AuthZ for users by acting as an OIDC ([OpenID Connect](#ODIC) flow) IdP itself.
In that sense, `fence` is both a `client` and `OpenID Connect Provider (OP)`.

### Fence as Client

Example:

- Google IAM is the OpenID Provider (OP)
- Fence is the client
- Google Calendar API is the resource provider

### Fence as OpenID Provider (OP)

- Fence is the OP
- A third-party application is the client
- Gen3 microservices (e.g. [`sheepdog`](https://github.com/uc-cdis/sheepdog)) are resource providers

### Example Flows

Note that the `3rd Party App` acts as the `client` in these examples.

[//]: # (See /docs folder for README on how to regenerate these sequence diagrams)

#### Flow: Client Registration

![Client Registration](docs/images/seq_diagrams/client_registration.png)

#### Flow: OpenID Connect

![OIDC Flow](docs/images/seq_diagrams/openid_connect_flow.png)

If the third-party application doesn't need to use any Gen3 resources (and just
wants to authenticate the user), they can just get
needed information in the `ID token` after the handshake is finished .

#### Flow: Using Tokens for Access

If a third-party application wants to use Gen3 resources like
`fence`/`sheepdog`/`peregrine`, they call those services with an `Access Token`
passed in an `Authorization` header.

![Using Access Token](docs/images/seq_diagrams/token_use_for_access.png)

#### Flow: Refresh Token Use

![Using Refresh Token](docs/images/seq_diagrams/refresh_token_use.png)

#### Flow: Refresh Token Use (Token is Expired)

![Using Expired Refresh Token](docs/images/seq_diagrams/refresh_token_use_expired.png)

#### Flow: Multi-Tenant Fence

The following diagram illustrates the case in which one fence instance should
use another fence instance as its identity provider.

A use case for this is when we setup a fence instance that uses NIH login as the IdP. Here, we go through a detailed approval process in NIH. Therefore we would like to do it once for a single lead Fence instance, allowing other fence instances simply to redirect to use the lead Fence as an IdP for logging in via NIH.

![Multi-Tenant Flow](docs/images/seq_diagrams/multi-tenant_flow.png)

#### Notes

See the [OIDC specification](http://openid.net/specs/openid-connect-core-1_0.html) for more details.
Additionally, see the [OAuth2 specification](https://tools.ietf.org/html/rfc6749).

## Accessing Data

Fence has multiple options that provide a mechanism to access data. The access
to data can be moderated through authorization information in a User Access File.

Users can be provided specific `privilege`'s on `projects` in the User Access
File. A `project` is identified by a unique authorization identifier AKA `auth_id`.

A `project` can be associated with various storage backends that store
object data for that given `project`. You can assign `read-storage` and `write-storage`
privilieges to users who should have access to that stored object data. `read` and 
`write` allow access to the data stored in a graph database.

Depending on the backend, Fence can be configured to provide users access to
the data in different ways.


### Signed URLS

Temporary signed URLs are supported in all major commercial clouds. Signed URLs are the most 'cloud agnostic' way to allow users to access data located in different platforms. Fence has the ability to request a specific file by its GUID (globally unique identifier) and retrieve a temporary
signed URL for object data in AWS or GCP that will provide direct access to that object.

### Google Cloud Storage


Whereas pre-signed URL is a cloud agnostic solution, services and tools on Google Cloud Platform prefer to use service account. Because of that, Fence provides support for generating temporary Google service account credentials to be easily used together with Google utilities.



#### Temporary Google Credentials

Fence issues temporary service account keys that will have the same
access a user does to data.
One can then use these credentials to AuthN as that
service account and manipulate the data within Google's Cloud Platform.

Service account keys expirations are managed by Fence, this design
should be revised after Google provides a way to issue temporary credentials
that work seamlessly with its infrastructure and tooling.


#### Google Account Linking

This is a deprecated method and is not recommended to be used generally.

Fence supports granting Google Account or Google Service Account owned by end-users temporary access to authorized data.

We call this process 'google account linking' because we are linking the user's Fence identity with his/her google identity.

##### a. Linking Google Personal Account

This allows an end-user to link their personal Google account with their Fence identity.


The data access is temporary, though there is a Fence endpoint to
extend access (without requiring the end-user to go through the entire
linking process again).

##### b. Linking Google Service Account

This allows an end-user to create their own personal Google Cloud Project
and register a Google Service Account from that project to have access
to data. While this method allows the most flexibility, it is also the
most complicated and requires strict adherence to a number of rules and
restrictions.

This method also requires Fence to have access to that
end-user's Google project. Fence is then able to monitor the project
for any anomalies that may unintentionally provide data access to entities
who should not have access.

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

The tests clear out the database every time they are run. If you want
to keep a persistent database for manual testing and general local usage,
create a second test database with a different name:

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

When you want to build an application that uses Gen3 resources on behalf of a user, you should register an OAuth client for this app.
Fence right now exposes client registration via admin CLI, because the Oauth2 client for a Gen3 commons needs approval from the sponsor of the commons. If you are an external developer, you should submit a support ticket.

As a Gen3 commons administrator, you can run following command for an approved client:
```bash
fence-create client-create --client CLIENT_NAME --urls OAUTH_REDIRECT_URL --username USERNAME
```
This command should output a tuple of `(client_id, client_secret)` which must be
saved by the OAuth client to use with
`fence`.

#### Register Internal Oauth Client

As a Gen3 commons administrator, if you want to create an oauth client that skips user consent step, use the following command:

```bash
fence-create client-create --client CLIENT_NAME --urls OAUTH_REDIRECT_URL --username USERNAME --auto-approve
```

#### Modify OAuth Client

```bash
fence-create client-modify --client CLIENT_NAME --urls http://localhost/api/v0/oauth2/authorize
```
That command should output any modifications to the client.

#### Delete OAuth Client

```bash
fence-create client-delete --client CLIENT_NAME
```
That command should output the result of the deletion attempt.

#### List OAuth Clients

```bash
fence-create client-list
```
That command should output the full records for any registered OAuth clients.

#### Set up for External Buckets on Google

```bash
fence-create link-external-bucket --bucket-name demo-bucket
fence-create link-bucket-to-project --bucket_id demo-bucket --bucket_provider google --project_auth_id test-project
```

The link-external-bucket returns an email for a Google group which needs to be added to access to the bucket `demo-bucket`.

## Token management

Fence utilizes [OpenID Connect](#OIDC) to generate tokens 
for clients. It can also provide tokens directly to a user.

Clients and users may then use those tokens with other
Gen3 Data Commons services to access protected endpoints that require specific permissions.

We use JSON Web Tokens (JWTs) as the format for all tokens of the following types:

- OIDC ID token: this token is used by the OIDC client to get a user's identity from the token content
- OIDC access token: this token can be sent to Gen3 services via bearer header and get protected resources.
- OIDC refresh token: this token can be sent to fence to request a new access / id token.



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
When the application is initialized, Fence loads in keypair files from the
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
and `PUBLIC KEY` (and in fact Fence will require that the private key files it
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
