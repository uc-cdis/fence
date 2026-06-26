# Task Tokens

Fence supports **Task Tokens**, a new type of access token for interacting with services that explicitly support them (e.g., Funnel/TES).

## Requesting a Task Token

Users request a task token by calling the credentials endpoint with a `task_token` query parameter specifying the desired token type:

```
GET /user/credentials/api/access_token?task_token=<task_token_type>
```

An `expires_in` query parameter may be included to request a specific token lifetime, in seconds:

```
GET /user/credentials/api/access_token?task_token=<task_token_type>&expires_in=<seconds>
```

If `expires_in` is omitted, the request defaults to the maximum lifetime the user is authorized for (see [User Authorization](#user-authorization) below). **This is expected to be the common case**.

Authorization for this request is governed by Arborist resource policies.

## Operator Setup

To enable Task Tokens on a Gen3 commons, configure the following fields in the Fence config:

```python
# Task token types that can be requested by users.
ALLOWED_TASK_TOKEN_TYPES: []

# The number of seconds after a task access token is issued until it expires.
# This max is applied even if the requesting user has access to request a
# longer-lived token in Arborist. This is configured per task token type,
# and falls back to MAX_ACCESS_TOKEN_TTL.
MAX_TASK_TOKEN_TTL: {}
# Example:
# TES: 345600
```

- **`ALLOWED_TASK_TOKEN_TYPES`** — an allowlist of task token types the commons supports. A user can only request a token type that appears in this list, regardless of their Arborist permissions.
- **`MAX_TASK_TOKEN_TTL`** — a per-token-type ceiling on token lifetime, in seconds. If a token type isn't listed here, its max TTL falls back to `MAX_ACCESS_TOKEN_TTL`. This cap is enforced unconditionally — it overrides whatever lifetime a user's Arborist policy would otherwise allow.

## User Authorization

Task token access is controlled entirely through Arborist resource paths under `/services/fence/task-token/`, granted via `user.yaml`.

### Basic access (the common case)

To request a task token of type `FOO`, a user must have `create` access on the `fence` service for the resource:

```
/services/fence/task-token/FOO
```

A user with this access may request a `FOO` task token of **any** lifetime, up to and including the operator-configured `MAX_TASK_TOKEN_TTL`. If the user omits `expires_in` from their request, they're granted a token with the maximum lifetime they're entitled to — this is the expected default behavior, and we recommend operators grant unscoped access (rather than time-scoped access, below) unless there's a specific need to restrict a user to a shorter-lived token.

### Time-scoped access (uncommon — for explicit, shorter-lived restrictions)

Access can optionally be scoped to a fixed, shorter token lifetime by appending a duration (in seconds) to the resource path:

```
/services/fence/task-token/FOO/100
```

A user with `create` access on this resource can request a `FOO` task token with `expires_in` that matches exactly **100 seconds**. Requesting a different value for `expires_in` will fail.

Note: For time scoped requests, the `expires_in` query parameter must be included when requesting for a task-token and must match the value in the user mapping.

This is intended for the uncommon case where a specific user, or token type, needs to be restricted to a token lifetime shorter than the operator-configured max. The exact value a user is restricted to should be communicated to them out-of-band (e.g. documentation, direct communication), since Fence does not expose a user's permitted value in its API responses.

> If an Arborist policy in `user.yaml` grants a user an exact value greater than `MAX_TASK_TOKEN_TTL`, that user will never be able to receive a task token via that policy — the request fails outright rather than being capped or floored. `MAX_TASK_TOKEN_TTL` in the Fence config is the authoritative ceiling, and a `user.yaml` entry should never be relied upon as the sole enforcement of the maximum.

### Example

```yaml
# user.yaml
authz:
  resources:
    - name: services
      subresources:
        - name: fence
          subresources:
            - name: task-token
              subresources:
                - name: FOO
                  subresources:
                    - name: "100"

users:
  u1:
    policies:
      - funnel_foo_task_token_100s  # grants create on /services/fence/task-token/FOO/100
```

With this policy, `u1` can request a `FOO` task token only with a TTL == 100 seconds. If `MAX_TASK_TOKEN_TTL` is configured lower than 100, `u1` will not be able to request a task token via this policy at all — the request fails rather than being capped to the lower value.

## Precedence Summary

| Layer | Effect |
|---|---|
| `ALLOWED_TASK_TOKEN_TYPES` (operator config) | Gates which token types exist on the commons at all |
| Arborist `create` access on `/services/fence/task-token/{type}` | Gates whether a user can request that type; grants any lifetime up to the operator max (the common case) |
| Arborist `create` access on `/services/fence/task-token/{type}/{seconds}` | Restricts a specific user to an exact TTL (the uncommon, explicitly-configured case). If this exact value exceeds `MAX_TASK_TOKEN_TTL`, requests via this policy fail outright |
| `MAX_TASK_TOKEN_TTL[{type}]` (operator config, falls back to `MAX_ACCESS_TOKEN_TTL`) | Hard ceiling on TTL for unscoped requests — applies unconditionally. For exact-value (time-scoped) grants, exceeding this ceiling causes the request to fail rather than being capped |

For unscoped (basic access) requests, the effective TTL is the **minimum** of the user-requested TTL (or the operator max, if `expires_in` was omitted) and the operator-configured `MAX_TASK_TOKEN_TTL`. For time-scoped (exact-value) requests, the granted TTL is exactly the Arborist-configured value — but only if that value does not exceed `MAX_TASK_TOKEN_TTL`; otherwise the request fails.

-----
### Next steps
* Update the SDK to use the task_token param
https://ctds-planx.atlassian.net/browse/MIDRC-1304
