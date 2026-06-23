# Task Tokens

Fence supports **Task Tokens**, a new type of access token for interacting with services that explicitly support them (e.g., Funnel/TES).

## Requesting a Task Token

Users request a task token by calling the credentials endpoint with a `task_token` query parameter specifying the desired token type:

```
GET /user/credentials/api/access_token?task_token=<task_token_type>
```

Authorization for this request is governed by Arborist resource policies (see [User Authorization](#user-authorization) below).

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

### Basic access

To request a task token of type `FOO`, a user must have `create` access on the `fence` service for the resource:

```
/services/fence/task-token/FOO
```

### Time-scoped access

Access can optionally be scoped to a maximum token lifetime by appending a duration (in seconds) to the resource path:

```
/services/fence/task-token/FOO/100
```

A user with `create` access on this resource can request a `FOO` task token with a TTL of **100 seconds or less**. Requesting a longer TTL will fail.

### Unscoped access

If no duration is specified in the resource path (i.e., access is granted on `/services/fence/task-token/FOO` rather than a path with a trailing time value), the user may request a `FOO` task token of **any** lifetime — subject to the operator-configured `MAX_TASK_TOKEN_TTL` ceiling described above.

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

With this policy, `u1` can request a `FOO` task token, but only with a TTL ≤ 100 seconds.

## Precedence Summary

| Layer | Effect |
|---|---|
| `ALLOWED_TASK_TOKEN_TYPES` (operator config) | Gates which token types exist on the commons at all |
| Arborist `create` access on `/services/fence/task-token/{type}` | Gates whether a user can request that type |
| Arborist `create` access on `/services/fence/task-token/{type}/{seconds}` | Caps the TTL a specific user can request for that type |
| `MAX_TASK_TOKEN_TTL[{type}]` (operator config, falls back to `MAX_ACCESS_TOKEN_TTL`) | Hard ceiling on TTL — applies even to users with unscoped/unlimited Arborist access |

The effective TTL for any request is the **minimum** of: the user-requested TTL, the user's Arborist-granted max (if scoped), and the operator-configured `MAX_TASK_TOKEN_TTL`.


-----
### Next steps
* Update the SDK to use the task_token param
https://ctds-planx.atlassian.net/browse/MIDRC-1304
