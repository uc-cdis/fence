# Shibboleth

The Shibboleth login flow is:
```
user
-> {fence}/login/shib?redirect={portal}
-> user login at {nih_shibboleth_idp}
-> nih idp POST to fence shibboleth and establish a shibboleth sp session
-> redirect to {fence}/login/shib/login that sets up fence session
-> redirect to portal
```

Fence checks the request parameter `ipd` and if it's equal to `shibboleth`, it then checks the request parameter `shib_idp` to know which identity provider to use (by default, if no `idp` and/or no `shib_idp` is specified, NIH is used). All valid identifiers for `shib_idp` are listed at https://login.bionimbus.org/Shibboleth.sso/DiscoFeed. Example IDPs:
- NIH iTrust (`shib_idp=urn:mace:incommon:nih.gov`. Default)
- InCommon (`shib_idp=urn:mace:incommon:uchicago.edu`)
- eduGAIN

**Warning:** Shibboleth login does not work if there are more than one replica, or if logging in through a canary.

## Configuration

### In login.bionimbus

The [Shibboleth dockerfile](../DockerfileShib) image is at https://quay.io/repository/cdis/fence-shib and is NOT compatible yet with python 3/the latest fence (for now, use fence 2.7.x).

`login.bionimbus.org` is under the Genomel AWS acccount. The deployment includes `revproxy` and `fenceshib`. Example deployment:
```
"versions": {
  "fenceshib": "quay.io/cdis/fence-shib:2.7.1",
  "revproxy": "quay.io/cdis/nginx:1.15.5-ctds"
}
```

### In the Commons which is set up with Shibboleth login

Register an OIDC client using [this `fence-create` command](https://github.com/uc-cdis/fence#register-internal-oauth-client), the redirect url should be `https://$COMMONS_DOMAIN/user/login/fence/login`.

Fence configuration:
```
OPENID_CONNECT:
  fence:
    api_base_url: 'https://example.com'
    client_id: ''
    client_secret: ''
    client_kwargs:
      # openid is required to use OIDC flow
      scope: 'openid'
      # callback after logging in through the other fence
      redirect_uri: '{{BASE_URL}}/login/fence/login'
    # The next 3 should not need to be changed if the provider is following
    # Oauth2 endpoint naming conventions
    authorize_url: 'https://login.bionimbus.org/oauth2/authorize'
    access_token_url: 'https://login.bionimbus.org/oauth2/token'
    name: 'Shib Login'
ENABLED_IDENTITY_PROVIDERS:
  providers:
    fence:
      name: 'Fence Multi-Tenant Login'
```

## Staging

`qa-biologin` is under the Genomel AWS acccount.

To use it, get the QA login.bionimbus IP and edit your local `/etc/hosts` to map this IP to `login.bionimbus.org`. Also edit `/etc/hosts` in the fence pod of the Commons that will be logging in through the QA login.bionimbus (this can be automated in `fence-deploy.yaml`).

## InCommon login

login.bionimbus should have provider `shibboleth` in section `OPENID_CONNECT` of the fence config.

In the Commons which is set up with InCommon login, the `authorize_url` should be `https://login.bionimbus.org/oauth2/authorize?idp=shibboleth&shib_idp={chosen_shib_idp}`.