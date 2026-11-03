# RFC 8693 Token Exchange

Fence can act as an [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)
Security Token Service (STS): a client presents a token from a trusted issuer at
the token endpoint, and Fence returns an ordinary Fence access token for that
token's subject.

- **A GA4GH passport.** Fence validates the passport and the visas inside it,
  syncs the authorization those visas describe to Arborist, and bounds the
  issued token by the earliest visa expiration.
- **Any other JWT** is rejected with `unsupported_grant_type`: exchanging a JWT
  that is not a passport is not currently supported.

## Configuration

```yaml
TOKEN_EXCHANGE:
  enabled: true
  allowed_subject_token_issuers:
    'https://stsstg.nih.gov':
      allowed_subject_token_types:
        - 'urn:ga4gh:params:oauth:token-type:passport'
      allowed_requested_token_types:
        - 'urn:ietf:params:oauth:token-type:access_token'
      allowed_clients:
        - 'my-exchange-client'
      max_token_lifetime: 600
      allowed_scopes:
        - 'openid'
        - 'user'
      require_passport_subject_visa_match: true
```

`allowed_subject_token_issuers` maps each trusted subject token issuer to the
policy for its tokens, and is required when the grant is enabled. Everything,
including which token types may be exchanged, is decided per issuer: there are
no instance-wide settings.

This list is deliberately **not** `GA4GH_VISA_ISSUER_ALLOWLIST`, which contains
this Fence instance's own `BASE_URL`. Reusing it would let a client exchange a
Fence-issued passport for a fresh Fence token indefinitely, sidestepping the
refresh token lifetime. Fence refuses to start if its own `BASE_URL` appears
here.

Passports from an issuer are only usable if the issuer is *also* in
`GA4GH_VISA_ISSUER_ALLOWLIST`, since that is what the visa validation inside the
passport sync checks against. If `GA4GH_PASSPORTS_TO_DRS_ENABLED` or
`GLOBAL_PARSE_VISAS_ON_LOGIN` is `true`, Fence refuses to start when an issuer
is missing from it. Otherwise it logs a warning, and every exchange of that
issuer's tokens is rejected.

| Per-issuer key | Default | Meaning |
|---|---|---|
| `allowed_subject_token_types` | none; required | `subject_token_type` values this issuer's tokens may be sent as |
| `allowed_requested_token_types` | `access_token` | `requested_token_type` values this issuer's tokens may be exchanged for |
| `allowed_clients` | any | names of the clients allowed to exchange this issuer's tokens. |
| `max_token_lifetime` | `ACCESS_TOKEN_EXPIRES_IN` | hard cap (seconds) on the issued token's lifetime. It can only shorten a token: a value above `ACCESS_TOKEN_EXPIRES_IN` has no effect, and Fence logs a warning at startup |
| `allowed_scopes` | the client's scopes | scopes an exchanged token may carry. Fence refuses to start if this is set without `openid` |
| `require_passport_subject_visa_match` | `true` | require the passport's subject to be among the identities its visas assert |

`allowed_subject_token_types` has no default so that a token type added in a
later Fence release is never turned on by an upgrade. Fence refuses to start if
either list names a type it has no handler for.

## Registering a client

The grant type must be enabled per client:

```bash
fence-create --arborist http://arborist-service client-create \
  --client my-exchange-client \
  --grant-types urn:ietf:params:oauth:grant-type:token-exchange \
  --allowed-scopes openid user \
  --policies my-exchange-client-policy
```

The client must be confidential. `client_secret_basic` and `client_secret_post`
are accepted; a public client cannot use this grant.

An exchanged token names the client in its `azp` claim, and Arborist authorizes
it only for what both the user *and* the client may access. Give the client
Arborist policies (defined in the user.yaml) with `--policies`, which
`fence-create` only registers in Arborist when given `--arborist`. A client with
no policies gets tokens that pass no Arborist check, whatever the passport
grants. `/user/user` still lists everything the user can access, since it
reports the user's access rather than the token's.

## Making a request

```bash
curl -X POST https://my-commons.org/user/oauth2/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$PASSPORT" \
  -d subject_token_type=urn:ga4gh:params:oauth:token-type:passport \
  -d scope="openid user"
```

Response (RFC 8693 §2.2.1):

```json
{
  "access_token": "eyJhb...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 600,
  "scope": "openid user"
}
```

When enabled, the grant type is advertised in `grant_types_supported` at
`/.well-known/openid-configuration`.

### Parameters

| Parameter | Supported | Notes |
|---|---|---|
| `subject_token` | required | a JWT; see `subject_token_type` |
| `subject_token_type` | required | `urn:ietf:params:oauth:token-type:jwt` or `urn:ga4gh:params:oauth:token-type:passport`. Either way the token must be a passport: any other JWT gets `unsupported_grant_type` as the JWT type, and `invalid_grant` as the passport type |
| `requested_token_type` | optional | defaults to, and currently must be, `urn:ietf:params:oauth:token-type:access_token`; must be allowed for the subject token's issuer |
| `scope` | optional | every requested scope must be allowed by both the client and the issuer's `allowed_scopes`, or the request fails with `invalid_scope`. Omitted, the token gets every scope both allow. `openid` is always included |
| `audience` / `resource` | rejected | `invalid_target`; the exchange only issues standard access tokens (`aud` `gen3`). Tokens scoped to one service are [task tokens](task_tokens.md), which the exchange does not currently issue |
| `actor_token` | rejected | `invalid_request`; delegation is not supported |

`urn:ga4gh:params:oauth:token-type:passport` is the identifier GA4GH AAI 1.2
defines for a passport, as the `requested_token_type` with which a broker issues
one. AAI does not define it as a `subject_token_type`, but RFC 8693 §3 allows any
URI there; Fence accepts it so a client can be explicit about what kind of JWT it
is sending.

### Errors

Errors are returned as RFC 6749 §5.2 error responses, except where noted.

| Error | When |
|---|---|
| `unsupported_grant_type` | token exchange is not enabled, with no `error_description`; or the subject token is a valid JWT that is not a passport, sent as `urn:ietf:params:oauth:token-type:jwt` |
| `invalid_client` | client authentication failed |
| `unauthorized_client` | the client is not registered for the grant, or is not in the issuer's `allowed_clients` |
| `invalid_request` | `subject_token` or `subject_token_type` is missing, `subject_token` is not a JWT, `actor_token` was sent, or a token type has no handler or is not allowed for the issuer |
| `invalid_target` | `audience` or `resource` was sent |
| `invalid_scope` | a requested scope is not available, or `openid` is not |
| `invalid_grant` | the issuer is not trusted; the subject token fails validation, has no `sub`, or is a passport without the `openid` scope; a JWT that is not a passport was sent as the passport type; the passport has no usable visas, or its visas do not describe its subject; or the authority behind it expires too soon to issue a token |
| HTTP 401 (not an RFC 6749 error response) | a user the exchange resolves is deactivated, or would have to be created while `ALLOW_NEW_USER_ON_LOGIN` is off |

## Supporting a new token type

Token-type behavior lives in handlers in `fence/oidc/token_exchange/`, selected
by the token type identifier. The grant
(`fence/oidc/grants/token_exchange_grant.py`) implements only RFC 8693 request
and response handling and the policy above, and does not change when a type is
added.

- A **subject token handler** (`SubjectTokenHandler`) answers: what does this
  incoming token mean, and what identity and authority does it carry? It
  implements `resolve_issuer` (the unverified issuer, for policy lookup only;
  it runs before the issuer's policy has allowed the type, so it must have no
  side effects), `validate` (no side effects), and `exchange` (side effects
  such as syncing authorization; resolves the Fence user, the time by which the
  issued token must expire, and optionally a narrower set of scopes).
- A **requested token handler** (`RequestedTokenHandler`) answers: how should
  Fence encode the accepted exchange as the token the client asked for? It
  implements `issue`, and is handed the user, client, granted scope and
  already-clamped lifetime.

To add a type:

1. Implement the handler (see `fence/oidc/token_exchange/base.py` for the
   interfaces).
2. Register its token type identifier in `SUBJECT_TOKEN_HANDLERS` or
   `REQUESTED_TOKEN_HANDLERS` in `fence/oidc/token_exchange/__init__.py`.
3. Operators opt in per issuer by adding the identifier to that issuer's
   `allowed_subject_token_types` / `allowed_requested_token_types`.
4. Add tests for the handler, and a grant-level test of the exchange.

The mapping from identifier to handler is deliberately code, not configuration:
configuration describes what Fence trusts and permits, not which class
implements a token type.
