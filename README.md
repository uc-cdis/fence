# Fence

[![Build Status](https://travis-ci.org/uc-cdis/fence.svg?branch=master)](https://travis-ci.org/uc-cdis/fence)

[![Coverage Status](https://coveralls.io/repos/github/uc-cdis/fence/badge.svg?branch=master)](https://coveralls.io/github/uc-cdis/fence?branch=master)

A `fence` separates protected resources from the outside world and allows
only trusted entities to enter.

Fence is a core service of the Gen3 stack that has multiple capabilities:

1. Act as an [auth broker](#auth-broker) to integrate with one or more [IdPs](#IdP) and provide downstream authentication and authorization for Gen3 services.
2. [Manage tokens](#token-management).
3. Act as an [OIDC provider](#oidc--oauth2) to support external applications to use Gen3 services.
4. [Issue short lived, cloud native credentials to access data in various cloud storage services](#accessing-data)


## Contents

1. [API Documentation](#API-documentation)
1. [Terminologies](./docs/introduction/terminology.md)
1. [Identity Providers](#identity-providers)
1. [OIDC & OAuth2](#oidc--oauth2)
1. [Accessing Data](#accessing-data)
1. [Setup](#setup)
1. [Token management](#token-management)
1. [fence-create](#fence-create-automating-common-tasks-with-a-command-line-interface)
1. [Default expiration times](#default-expiration-times-in-fence)


## API Documentation

[OpenAPI documentation available here.](http://petstore.swagger.io/?url=https://raw.githubusercontent.com/uc-cdis/fence/master/openapis/swagger.yaml)

YAML file for the OpenAPI documentation is found in the `openapis` folder (in
the root directory); see the README in that folder for more details.


## Identity Providers

Fence can be configured to support different Identity Providers (IdPs) for AuthN.
At the moment, supported IDPs include:

- Google
- [Shibboleth](docs/misc/fence_shibboleth.md)
  - NIH iTrust
  - InCommon
  - eduGAIN
- CILogon
- Cognito
- Synapse
- Microsoft
- ORCID
- RAS

## Access Control / Authz

Currently fence works with another Gen3 service named
[arborist](https://github.com/uc-cdis/arborist) to implement attribute-based access
control for commons users. The YAML file of access control information (see
[#create-user-access-file](#create-user-access-file)) contains a section `authz` which are data sent to
arborist in order to set up the access control model.

## Accessing Data

Fence has multiple options that provide a mechanism to access data. The access
to data can be moderated through authorization information in a User Access File.

Users can be provided specific `privilege`'s on `projects` in the User Access
File. A `project` is identified by a unique authorization identifier AKA `auth_id`.

A `project` can be associated with various storage backends that store
object data for that given `project`. You can assign `read-storage` and `write-storage`
privileges to users who should have access to that stored object data. `read` and
`write` allow access to the data stored in a graph database.

Depending on the backend, Fence can be configured to provide users access to
the data in different ways.


### Signed URLS

Temporary signed URLs are supported in all major commercial clouds. Signed URLs are the most 'cloud agnostic' way to allow users to access data located in different platforms.

Fence has the ability to request a specific file by its GUID (globally unique identifier) and retrieve a temporary signed URL for object data in AWS or GCP that will provide direct access to that object.

### Google Cloud Storage

Whereas pre-signed URL is a cloud agnostic solution, services and tools on Google Cloud Platform prefer to use Google's concept of a "Service Account". Because of that, Fence provides a few more methods to access data in Google.

See [Fence and Google](docs/misc/google_architecture.md) for more details on data access methods specific to Google.


