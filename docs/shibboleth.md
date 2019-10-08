# Shibboleth / InCommon login

Shibboleth is set up at login.bionimbus.org and lets us log in through InCommon by specifying the `shib_idp` parameter (as of fence release 4.7.0 and fence-shib release 2.7.2). If no `shib_idp` is specified (or if using an earlier fence version), users will be redirected to the NIH login page by default.

## Login flow

The `/login/fence` endpoint (multi-tenant fence login endpoint) accepts the query parameters `ipd` and `shib_idp`. If `idp` is set to `shibboleth`, fence adds the `ipd` and `shib_idp` parameters to the authorization URL (typically `https://login.bionimbus.org/oauth2/authorize`) before redirecting the user.

The `/authorize` endpoint accepts the query parameters `ipd` and `shib_idp`. If `idp` is set to `shibboleth`, fence adds the `shib_idp` parameter to the login URL before redirecting the user.

The `/login/shib` endpoint accepts the query parameter `shib_idp`. Fence checks this parameter to know which Shibboleth identity provider to use (by default, if no `shib_idp` is specified, NIH is used by default). All all valid identifiers for `shib_idp` are listed at https://login.bionimbus.org/Shibboleth.sso/DiscoFeed (`entityID`).

The Shibboleth login flow when no `shib_idp` is specified is:
```
user
-> {fence}/login/shib?redirect={portal}
-> user login at {nih_shibboleth_idp}
-> nih idp POST to fence shibboleth and establish a shibboleth sp session
-> redirect to {fence}/login/shib/login that sets up fence session
-> redirect to portal
```

## Configuration

### In login.bionimbus.org

The [Shibboleth dockerfile](../DockerfileShib) image is at https://quay.io/repository/cdis/fence-shib and is NOT compatible yet with python 3/the latest fence (for now, use fence 2.7.x).

`login.bionimbus.org` is under the Genomel AWS acccount. The deployment only includes `revproxy` and `fenceshib`. The fence configuration enables the `shibboleth` provider:

```
OPENID_CONNECT:
  shibboleth:
    [...]
ENABLED_IDENTITY_PROVIDERS:
  providers:
    shibboleth:
      name: Shibboleth Login
```

Note that because fenceshib is not compatible with the latest fence yet, we must use the deprecated `providers` field instead of the newer `login_options` field.

The Shibboleth configuration can be checked inside the fenceshib pod under `/etc/shibboleth/`.

**Warning:** Shibboleth login does not work if there are more than one replica, or if logging in through a canary.

### In the Commons which is set up with InCommon login

Register an OIDC client using [this `fence-create` command](https://github.com/uc-cdis/fence#register-internal-oauth-client), the redirect url should be `<COMMONS_URL>/user/login/fence/login`.

The fence configuration enables the `fence` provider (multi-tenant fence setup):
```
OPENID_CONNECT:
  fence:
    [...]
```

Setup example:
```
ENABLED_IDENTITY_PROVIDERS:
  default: fence
  login_options:
    - name: 'NIH Login by default'
      idp: fence
    - name: 'NIH Login'
      idp: fence
      shib_idps:
       - urn:mace:incommon:nih.gov
    - name: 'UChicago Login'
      idp: fence
      shib_idps:
       - urn:mace:incommon:uchicago.edu
    - name: 'InCommon Login list'
      idp: fence
      shib_idps:
        - urn:mace:incommon:nih.gov
        - urn:mace:incommon:uchicago.edu
    - name: 'InCommon Login all'
      idp: fence
      shib_idps: '*'
```

Several login options can use the same provider (`idp`). Each option that uses the `fence` provider can specify one or more InCommon IDPs `shib_idps` in a list, _or_ the wildcard string `'*'` to enable all available InCommon IDPs (be careful not to omit the quotes when using the wildcard). If no `shib_idps` are specified, fence will default to NIH login.

## Staging

`qa-biologin` is under the Genomel AWS acccount.

To use it, get the QA login.bionimbus IP and edit your local `/etc/hosts` to map this IP to `login.bionimbus.org`. Also edit `/etc/hosts` in the fence pod of the Commons that will be logging in through the QA login.bionimbus (this can be automated in `fence-deploy.yaml`).
