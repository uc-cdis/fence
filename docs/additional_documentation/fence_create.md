## fence-create: Automating common tasks with a command line interface

fence-create is a command line utility that is bundled with fence and allows you to automate some commons tasks within fence. For the latest and greatest run the command `fence-create --help`.

WARNING: fence-create directly modifies the database in some cases and may circumvent security checks (most of these utilities are used for testing). BE CAREFUL when you're running these commands and make sure you know what they're doing.


### Register Internal Oauth Client

As a Gen3 commons administrator, if you want to create an oauth client that skips user consent step, use the following command:

```bash
fence-create client-create --client CLIENT_NAME --urls OAUTH_REDIRECT_URL --username USERNAME --auto-approve (--expires-in 30)
```

The optional `--expires-in` parameter allows specifying the number of days until this client expires.

### Register an Implicit Oauth Client

As a Gen3 commons administrator, if you want to create an implicit oauth client for a webapp:

```bash
fence-create client-create --client fancywebappname --urls 'https://betawebapp.example/fence
https://webapp.example/fence' --public --username fancyapp --grant-types authorization_code refresh_token implicit
```

If there are more than one URL to add, use space to delimit them like this:

```bash
fence-create client-create --urls 'https://url1/' 'https://url2/' --client ...
```

To specify allowed scopes, use the `allowed-scopes` argument:
```bash
fence-create client-create ...  --allowed-scopes openid user data
```

### Register an Oauth Client for a Client Credentials flow

The OAuth2 Client Credentials flow is used for machine-to-machine communication and scenarios in which typical authentication schemes like username + password do not make sense. The system authenticates and authorizes the app rather than a user. See the [OAuth2 specification](https://www.rfc-editor.org/rfc/rfc6749#section-4.4) for more details.

As a Gen3 commons administrator, if you want to create an OAuth client for a client credentials flow:

```bash
fence-create client-create --client CLIENT_NAME --grant-types client_credentials (--expires-in 30)
```

This command will return a client ID and client secret, which you can then use to obtain an access token:

```bash
curl --request POST https://FENCE_URL/oauth2/token?grant_type=client_credentials -d scope="openid user" --user CLIENT_ID:CLIENT_SECRET
```

The optional `--expires-in` parameter allows specifying the number of *days* until this client expires. The recommendation is to rotate credentials with the `client_credentials` grant at least once a year (see [Rotate client credentials](#rotate-client-credentials) section).

NOTE: In Gen3, you can grant specific access to a client the same way you would to a user. See the [user.yaml guide](https://github.com/uc-cdis/fence/blob/master/docs/additional_documentation/user.yaml_guide.md) for more details.

NOTE: Client credentials tokens are not linked to a user (the claims contain no `sub` or `context.user.name` like other tokens). Some Gen3 endpoints that assume the token is linked to a user, or whose logic require there being a user, do not support them. For an example of how to adapt an endpoint to support client credentials tokens, see [here](https://github.com/uc-cdis/requestor/commit/a5078fae27fa258ac78045cf2bb89cb2104f53cf). For an example of how to explicitly reject client credentials tokens, see [here](https://github.com/uc-cdis/requestor/commit/0f4974c25343d2185c7cdb48dcdeb58f97800672).

### Modify OAuth Client

```bash
fence-create client-modify --client CLIENT_NAME --urls http://localhost/api/v0/oauth2/authorize
```

That command should output any modifications to the client. Similarly, multiple URLs are
allowed here too.

Add `--append` argument to add new callback urls or allowed scopes to existing client (instead of replacing them) using `--append --urls` or `--append --allowed-scopes`
```bash
fence-create client-modify --client CLIENT_NAME --urls http://localhost/api/v0/new/oauth2/authorize --append (--expires-in 30)
```

### Rotate client credentials

Use the `client-rotate` command to receive a new set of credentials (client ID and secret) for a client. The old credentials are NOT deactivated and must be deleted or expired separately (see [Delete Expired OAuth Clients](#delete-expired-oauth-clients) section). This allows for a rotation without downtime.

```bash
fence-create client-rotate --client CLIENT_NAME (--expires-in 30)
```

Note that the `usersync` job must be run after rotating the credentials so that the new client ID is granted the same access as the old one.

### Delete OAuth Client

```bash
fence-create client-delete --client CLIENT_NAME
```
That command should output the result of the deletion attempt.

### Delete Expired OAuth Clients

```bash
fence-create client-delete-expired
```

To post a warning in Slack about any clients that expired or are about to expire:

```bash
fence-create client-delete-expired --slack-webhook <url> --warning-days <default 7: only post about clients expiring in under 7 days>
```


### List OAuth Clients

```bash
fence-create client-list
```
That command should output the full records for any registered OAuth clients.

### Set up for External Buckets on Google

```bash
fence-create link-external-bucket --bucket-name demo-bucket
fence-create link-bucket-to-project --bucket_id demo-bucket --bucket_provider google --project_auth_id test-project
```

The link-external-bucket returns an email for a Google group which needs to be added to access to the bucket `demo-bucket`.

### Notify users who are blocking service account registration

```bash
fence-create notify-problem-users --emails ex1@gmail.com ex2@gmail.com --auth_ids test --google_project_id test-google
```

`notify-problem-users` emails users in the provided list (can be fence user email or linked google email) who do not have access to any of the auth_ids provided. Also accepts a `check_linking` flag to check that each user has linked their google account.
