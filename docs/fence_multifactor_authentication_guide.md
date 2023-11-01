# Fence Multifactor Authentication Guide

Fence is capable of using token claims from IdPs to identify when multifactor authentication (MFA) was used during the authentication process.

## File Level Enforcement
To restrict access to files to user who've authenticated with MFA, the following resource *MUST* be present in the indexd record's `authz`:
`/multifactor_auth`

And the following configs must be updated:
- fence-config.yaml
- user.yaml

### fence-config.yaml changes

MFA claim checking is configured on a per-IdP basis. For a given IdP, define the name of the claim in the id_token and is possible values that indicate MFA. If the id_token claim value matches at least one value in the configured multifactor_auth_claim_info.values, then "/multifactor_auth" resource will be assigned to the user.

For example, Okta may issue the following id_token when MFA is used:
```
{
  "amr": ["otp", "pwd"],
  "aud": "6joRGIzNCaJfdCPzRjlh",
  "auth_time": 1311280970,
  "exp": 1311280970,
  "iat": 1311280970,
  "idp": "00ok1u7AsAkrwdZL3z0g3",
  "iss": "https://$"
  "jti": "Tlenfse93dgkaksginv",
  "sub": "00uk1u7AsAk6dZL3z0g3",
  "ver": 1
}
```

And fence-config.yaml is configured as follows:
```
OPENID_CONNECT:
  okta:
    client_id: 'redacted'
    client_secret: 'redacted'
    multifactor_auth_claim_info:
      claim: 'amr'
      values: [  "mfa", "otp", "sms" ]
```

Then fence will assign the "/multifactor_auth" resource to the user in Arborist.

### user.yaml changes
The `mfa_policy` policy and `multifactor_auth` resource must be added to user.yaml so the appropriate policy and resource are created in arborist when usersync runs.

NOTE: The role_ids provided here are an example and should be changed to the appropriate arborist roles for the commons.

Add the following to the `resources` section:
```yaml
  - name: multifactor_auth
```

Add the following the `policies` section:
```yaml
- id: mfa_policy
  role_ids:
   - read-storage
   - read
   resource_paths:
   - /multifactor_auth
```
