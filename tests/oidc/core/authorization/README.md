In this folder, test the [authorization
endpoint](http://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint)
for OIDC compliance.

The basic set of data sent to the authorization endpoint looks like this (line
breaks included for readability only:
```
?client_id=some-client
&redirect_uri=https%3A%2F%2Fsome.client.net
&response_type=code
&scope=openid
&state=VzVtLhh6
```
and should also include `confirm=yes` for a POST operation for the to skip
consenting to the requested scopes.

The response should be a 302 FOUND with the `Location` field in response
headers containing a URL which contains the code to use for obtaining a token.

Most tests for the authorization endpoint will do at least these checks for a
successful response (modifying ``data`` as necessary for specific tests):
```python
auth_response = oauth2.post_authorize(client, oauth_client, data=data, confirm=True)
assert auth_response.status_code == 302
assert 'Location' in auth_response.headers
assert oauth2.code_from_authorize_response(auth_response)
```
