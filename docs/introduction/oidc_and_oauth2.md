## OIDC & OAuth2

Fence acts as a central broker that supports multiple IdPs.
At the same time, it acts as an IdP itself.
In that sense, `fence` is both an `RP` and an `OP`.

### Fence as RP

Example:

- Google IAM is the OpenID Provider (OP)
- Fence is the Relying Party (RP)
- Google Calendar API is the resource provider

### Fence as OP

- Fence is the OpenID Provider (OP)
- A third-party application is the Relying Party (RP)
- Gen3 microservices (e.g. [`sheepdog`](https://github.com/uc-cdis/sheepdog)) are resource providers

### Example Flows

Note that the `3rd Party App` acts as the `RP` in these examples.

[//]: # (See /docs folder for README on how to regenerate these sequence diagrams)

#### Flow: Client Registration

![Client Registration](docs/images/seq_diagrams/client_registration.png)

#### Flow: OpenID Connect

In the following flow, Fence and the IdP together constitute an `OP`.
Fence, by itself, acts as an OAuth 2.0 Auth Server; the IdP enables the additional implementation of OIDC (by providing AuthN). From an OIDC viewpoint, therefore, Fence and the IdP can be abstracted into one `OP`.

![OIDC Flow](docs/images/seq_diagrams/openid_connect_flow.png)

If the third-party application doesn't need to use any Gen3 resources (and just
wants to authenticate the user), they can just get
needed information in the `ID token` after the handshake is finished .

#### Flow: Using Tokens for Access

If a third-party application wants to use Gen3 resources like
`fence`/`sheepdog`/`peregrine`, they call those services with an `Access Token`
passed in an `Authorization` header.

In the following flow, `3rd Party App` is the `RP`; `Protected Endpoint` is an endpoint of a Gen3 Resource (the `microservice`), and both of these are part of a `resource server`; and `Fence` is the `OP`. Here, importantly, `Fence` may be interfacing with another IdP _or_ with another `Fence` instance in order to implement the OIDC layer. Either way, note that the `Fence` blob in this diagram actually abstracts Fence in concert with some IdP, which may or may not also be (a different instance of) Fence.

![Using Access Token](docs/images/seq_diagrams/token_use_for_access.png)

#### Flow: Refresh Token Use

![Using Refresh Token](docs/images/seq_diagrams/refresh_token_use.png)

#### Flow: Refresh Token Use (Token is Expired)

![Using Expired Refresh Token](docs/images/seq_diagrams/refresh_token_use_expired.png)

#### Flow: Multi-Tenant Fence

The following diagram illustrates the case in which one fence instance
uses another fence instance as its identity provider.

A use case for this is when we setup a fence instance that uses NIH login as the IdP. Here, we go through a detailed approval process in NIH. Therefore we would like to do it only once for a single lead Fence instance, and then allow other fence instances to simply redirect to use the lead Fence as an IdP for logging in via NIH.

In the following flow, `Fence (Client Instance)` is an OP relative to `OAuth Client`, but an RP relative to `Fence (IDP)`.

![Multi-Tenant Flow](docs/images/seq_diagrams/multi-tenant_flow.png)

#### Notes

See the [OIDC specification](http://openid.net/specs/openid-connect-core-1_0.html) for more details.
Additionally, see the [OAuth2 specification](https://tools.ietf.org/html/rfc6749).
