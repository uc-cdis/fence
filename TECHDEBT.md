#  Tech debt

### Using 'aud' claim for scopes
- Observed: July 2020
- Impact: (If this tech debt affected your work somehow, add a +1 here with a date and note)
  - +1 Zoe 2020 July 15 This is an example of a +1
  - +1 Vahid Oct 2020

##### Problem:
Fence puts OAuth2 scopes into the 'aud' claim of access tokens.
##### Why it was done this way:
We don't know.
##### Why this way is problematic:
Per RFC7519 the aud claim [is not meant for scopes](https://tools.ietf.org/html/rfc7519#section-4.1.3).
##### What the solution might be:
GA4GH AAI [already requires](https://github.com/ga4gh/data-security/blob/master/AAI/AAIConnectProfile.md#access_token-issued-by-broker) that a 'scope' claim be included in access tokens issued by Passport Brokers. So as of July 2020 we will put scopes in the 'scope' claim. However, this is in addition to keeping them in the 'aud' claim. Ideally we would only have the scopes in the 'scope' claim.
##### Why we aren't already doing the above:
Fence presently guards several endpoints (e.g. /data, signed urls, SA registration) by checking the scopes in the 'aud' claim of the JWT. This code would need to be changed.
##### Next steps:
Address above.
##### Other notes:
n/a


### Not validating aud claim in Bearer tokens
##### Problem:
- The login_required decorator purports to enforce requirement of a user session (see fence/auth.py).
- However, it also allows falling back on the presence of a Bearer token in the request.
- In the latter case, the decorator calls has_oauth, which validates the JWT and checks that it has the right scopes. However, the validation does not verify the 'aud' claim. This is a security risk in settings where one Authorization server is issuing JWTs for multiple Resource servers. See [RFC 6819 5.1.5.5](https://tools.ietf.org/html/rfc6819#section-5.1.5.5).
##### Historical context:
- Fence used to use the 'aud' claim for scopes, overriding conventional 'aud' validation; the 'aud' claim was therefore not being used or validated correctly.
- Now scopes have been moved into a custom 'scope' claim with custom 'scope' validation, and 'aud' is populated with client_id (required by OIDC for id_tokens). 'aud' validation has reverted to the conventional validation.
- However, this means that now Fence cannot consume its own JWTs in its capacity as its own Resource server, since it does not identify as the client_id.
- In order to keep allowing the affected Fence endpoints to be used with a Bearer token, has_oauth currently skips validation of the 'aud' claim.
##### Possible solution:
- Along with client_id, put iss in aud as well? Need to think about whether this captures all current use cases, e.g. when Fence is trusted as Auth server to different Resource servers with different domains.
