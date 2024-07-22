
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
  "iss": "https://commons.org",
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
  "iss": "https://commons.org",
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
  "iss": "https://commons.org",
  "jti": "c72e5573-39fa-4391-a445-191e370b7cc5",
  "exp": 1517010902,
  "iat": 1516982102
}
```