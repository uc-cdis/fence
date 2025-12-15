
## Setup

### Install Requirements and Fence

Install [Poetry](https://python-poetry.org/docs/#installation).

```bash
# Install Fence and dependencies
poetry install
```

### Create Configuration File

Fence requires a configuration file to run. We have a command line
utility to help you create one based on a default configuration.

The configuration file itself will live outside of this repo (to
prevent accidentally checking in sensitive information like database passwords).

To create a new configuration file from the default configuration:

```bash
python cfg_help.py create
```

This file will be placed in one of the default search directories for Fence.

To get the exact path where the new configuration file was created, use:

```bash
python cfg_help.py get
```

The file should have detailed information about each of the configuration
variables. **Remember to fill out the new configuration file!**

Once you have done so, you can run `alembic upgrade head` to generate the tables needed
to run fence.

#### Other Configuration Notes

* Fence will look for configuration files from a list of search directories (
which are currently defined in `fence/settings.py`.)
* For more configuration options (such as having multiple different config
files for development), see the `cfg_help.py` file.

### Set Up Databases

The tests clear out the database every time they are run. If you want
to keep a persistent database for manual testing and general local usage,
create a second test database with a different name:

> NOTE: Requires a minimum of Postgres v9.4 (because of `JSONB` types used)

```bash
# Create test database(s).
# This one is for automated tests, which clear the database after running;
psql -U test postgres -c 'create database fence_test_tmp'
userdatamodel-init --db fence_test_tmp
# This one is for manual testing/general local usage; Your config
# should have `fence_test` in the `DB` variable.
psql -U test postgres -c 'create database fence_test'
userdatamodel-init --db fence_test --username test --password test
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
openssl genpkey -algorithm RSA -out jwt_private_key.pem -pkeyopt rsa_keygen_bits:2048

# Generate the public key.
openssl rsa -pubout -in jwt_private_key.pem -out jwt_public_key.pem

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


### Create User Access File

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

### Register OAuth Client

When you want to build an application that uses Gen3 resources on behalf of a user, you should register an OAuth client for this app.
Fence right now exposes client registration via admin CLI, because the Oauth2 client for a Gen3 commons needs approval from the sponsor of the commons. If you are an external developer, you should submit a support ticket.

As a Gen3 commons administrator, you can run following command for an approved client:
```bash
fence-create client-create --client CLIENT_NAME --urls OAUTH_REDIRECT_URL --username USERNAME
```
This command should output a tuple of `(client_id, client_secret)` which must be
saved by the OAuth client to use with
`fence`.

## Quickstart with Helm

You can now deploy individual services via Helm!
Please refer to the Helm quickstart guide HERE (https://github.com/uc-cdis/fence/blob/master/docs/additional_documentation/quickstart_helm.md)
