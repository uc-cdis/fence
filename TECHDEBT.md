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
