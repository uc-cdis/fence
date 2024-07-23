## Terminologies

### AuthN

Authentication - establishes "who you are" with the application through communication with an [Identity Provider](#IdP).

### AuthZ

Authorization - establishes "what you can do" and "which resources you have access to" within the application.

### IdP

Identity Provider - the service that lets a user login and provides the identity of the user to downstream services. Examples: Google login, University login, NIH Login.

### Auth broker

An interface which enables a user to authenticate using any of multiple IdPs.

### OAuth2

A widely used AuthZ protocol for delegating access to an application to use resources on behalf of a user.

https://tools.ietf.org/html/rfc6749

https://oauth.net/2/

#### Client

OAuth 2.0 Client - An application which makes requests for protected resources (on a resource server) on behalf of a resource owner (end-user) and with the resource owner's authorization.

#### Auth Server

OAuth 2.0 Authorization Server - A server which issues access tokens to the client after successfully authenticating the resource owner and obtaining authorization.

#### Access Token

A string, issued by the auth server to the client, representing authorization credentials used to access protected resources (on a resource server).

### OIDC

OpenID Connect - an extension of OAuth2 which provides an AuthN layer on top of the OAuth 2.0 AuthZ layer. It introduced a new type of token, the id token, that is specifically designed to be consumed by clients to get the identity information of the user.

http://openid.net/specs/openid-connect-core-1_0.html

#### OP

OpenID Provider - an OAuth 2.0 Authentication Server which also implements OpenID Connect.

#### RP

Relying Party - an OAuth 2.0 Client which uses (requests) OpenID Connect.
