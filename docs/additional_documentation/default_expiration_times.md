## Default Expiration Times in Fence

Tables contain various artifacts in fence that have temporary lifetimes and their default values.

### Tokens, Sessions, and Signed URLs

| Name                         | Lifetime            | Extendable? | Maximum Lifetime                                              | Details                                                                                              |
| ---------------------------- | ------------------- | ----------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Access Token                 | 20 minutes          | TRUE        | Life of the refresh token, or 8 hours for a browser session   | `ACCESS_TOKEN_EXPIRES_IN`. Issued to OIDC clients and to browser sessions                            |
| Sliding Session Window       | 15 minutes          | TRUE        | 8 hours                                                       | `SESSION_TIMEOUT` and `SESSION_LIFETIME`. access_token cookies get generated automatically if the session is still active, when the token is missing, expired, or within `ACCESS_TOKEN_RENEWAL_THRESHOLD` seconds of expiring |
| Refresh Token                | 30 days             | FALSE       | N/A                                                           | `REFRESH_TOKEN_EXPIRES_IN` is both the default and the max                                           |
| API Key                      | 30 days             | FALSE       | N/A                                                           | `MAX_API_KEY_TTL`. Can optionally provide a shorter expiration                                       |
| Access Token from an API Key | 1 hour              | TRUE        | 1 hour per token, and never past the API key's own expiration | `MAX_ACCESS_TOKEN_TTL` is both the default and the max at `/credentials/api/access_token`. A request that would outlive the API key is rejected rather than shortened |
| Task Token                   | Per task token type | TRUE        | Per task token type                                           | `MAX_TASK_TOKEN_TTL` per type, falling back to `MAX_ACCESS_TOKEN_TTL`. No task token types are allowed by default |
| Signed URL (AWS or Google)   | Up to 1 hour        | FALSE       | N/A                                                           | `MAX_PRESIGNED_URL_TTL`. Can optionally provide an expiration less than 1 hour                       |

### Google Account Linking and Service Accounts

> NOTE: "SA" in the below table stands for Service Account

> NOTE: Google account linking and proxy group management are under review for
> deprecation. Do not build new functionality on the lifetimes below.

| Name                          | Lifetime   | Extendable? | Maximum Lifetime | Details                                                                                              |
| ----------------------------- | ---------- | ----------- | ---------------- | ---------------------------------------------------------------------------------------------------- |
| User's Google Account Linkage | Indefinite | N/A         | N/A              | The linkage itself never expires; only the Google account access below does                          |
| User's Google Account Access  | 1 day      | TRUE        | N/A              | `GOOGLE_ACCOUNT_ACCESS_EXPIRES_IN`. After AuthN, how long we associate a Google email with the given user. Can optionally provide an expiration less than 1 day |
| User's SA Account Access      | 7 days     | TRUE        | N/A              | `GOOGLE_USER_SERVICE_ACCOUNT_ACCESS_EXPIRES_IN`. Access to data (e.g. length it stays in the proxy group). Can optionally provide an expiration less than 7 days |
| Client SA (for User) Key      | 10 days    | FALSE       | N/A              | Obtained by the user themselves for temp access through `/credentials/google`. Set by cirrus's `SERVICE_KEY_EXPIRATION_IN_DAYS`, not a fence config. Can optionally provide an expiration less than 10 days |
| User Primary SA Key           | 30 days    | FALSE       | N/A              | `GOOGLE_SERVICE_ACCOUNT_KEY_FOR_URL_SIGNING_EXPIRES_IN`. Used for Google URL signing                 |
