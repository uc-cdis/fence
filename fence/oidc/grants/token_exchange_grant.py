"""
RFC 8693 (OAuth 2.0 Token Exchange) support for Fence.

Fence acts as a Security Token Service (STS) in what the GA4GH AAI OpenID
Connect profile calls a Claim Clearinghouse: a client presents a GA4GH passport
issued by a trusted broker (e.g. RAS) as the ``subject_token``, Fence validates
the passport and the visas inside it, syncs the authorization those visas
describe to Arborist, and returns an ordinary Fence access token.

This is impersonation, not delegation -- the issued token acts as the passport
subject -- so ``actor_token`` is rejected rather than supported.

Scope of this implementation:

- Subject token MUST be a GA4GH passport JWT. The other AAI artifact, a
  "passport-scoped access token", would require Fence to call the broker's
  userinfo endpoint with a credential that was not issued to Fence, which is an
  audience-confusion risk (RFC 8693 section 5) and a broker policy question.
- ``audience``/``resource`` are not supported and are rejected with
  ``invalid_target``, since a Fence access token is not scoped to a single
  downstream service.
- No refresh token is issued. The issued token's lifetime is bounded by the
  visas that justified it; a client that needs continued access re-exchanges the
  passport, which re-runs the sync and re-checks visa freshness.

References:
    RFC 8693: https://datatracker.ietf.org/doc/html/rfc8693
    GA4GH AAI: https://ga4gh.github.io/data-security/aai-openid-connect-profile
"""

import time

import flask
from authlib.oauth2.rfc6749.errors import (
    InvalidGrantError,
    InvalidRequestError,
    InvalidScopeError,
    OAuth2Error,
    UnauthorizedClientError,
    UnsupportedGrantTypeError,
)
from authlib.oauth2.rfc6749.grants import BaseGrant, TokenEndpointMixin
from authlib.oauth2.rfc6749.util import scope_to_list
from authutils.token.core import get_iss
from cdislogging import get_logger

from fence.config import config
from fence.jwt.validate import validate_jwt
from fence.models import ClientAuthType, GrantType, IssSubPairToUser

# NOTE: fence.resources.ga4gh.passports is imported inside the methods that use
# it. It pulls in fence.scripting.fence_create, which imports blueprints, which
# would be a circular import from here (this module is imported while the OIDC
# server is being built).

logger = get_logger(__name__)


#: RFC 8693 section 2.1
GRANT_TYPE_TOKEN_EXCHANGE = GrantType.token_exchange.value

#: RFC 8693 section 3 token type identifiers
TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"

#: Private token type identifier for a GA4GH passport. RFC 8693 section 3 allows
#: any URI as a token type identifier; there is no registered identifier for a
#: passport, so this exists to let a client say what kind of JWT it is sending.
TOKEN_TYPE_GA4GH_PASSPORT = "urn:ga4gh:params:oauth:token-type:passport"

#: Subject token types this grant knows how to resolve to an identity. Both mean
#: "a GA4GH passport JWT".
SUPPORTED_SUBJECT_TOKEN_TYPES = [TOKEN_TYPE_JWT, TOKEN_TYPE_GA4GH_PASSPORT]

#: Fence only issues access tokens from this grant.
SUPPORTED_REQUESTED_TOKEN_TYPES = [TOKEN_TYPE_ACCESS_TOKEN]


class InvalidTargetError(OAuth2Error):
    """
    The authorization server is unable or unwilling to issue a token for the
    requested target service (the ``audience`` or ``resource`` parameter).

    https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2

    Authlib 1.6 does not ship this error, since it is specific to RFC 8693.
    """

    error = "invalid_target"


class TokenExchangeGrant(BaseGrant, TokenEndpointMixin):
    """
    Implement the RFC 8693 token exchange grant.

    ``validate_token_request`` establishes that the request is well formed, that
    this client is allowed to exchange tokens from this issuer, and that the
    passport itself is authentic. ``create_token_response`` does the part with
    side effects: sync the visas and mint a token.
    """

    GRANT_TYPE = GRANT_TYPE_TOKEN_EXCHANGE

    # deliberately excludes "none": a public client that can exchange passports
    # is a passport-laundering service
    TOKEN_ENDPOINT_AUTH_METHODS = [
        ClientAuthType.basic.value,
        ClientAuthType.post.value,
    ]

    def validate_token_request(self):
        """
        Validate the token exchange request per RFC 8693 section 2.1, plus the
        per-issuer policy in ``config["TOKEN_EXCHANGE"]``.

        Raises:
            OAuth2Error: if the request or the subject token is not acceptable
        """
        # the grant is always registered on the server, so whether it is enabled
        # is checked here rather than at registration time (config is not loaded
        # when the server is built)
        if not config.get("TOKEN_EXCHANGE", {}).get("enabled"):
            raise UnsupportedGrantTypeError(self.GRANT_TYPE)

        client = self.authenticate_token_endpoint_client()
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(
                f"The client is not authorized to use 'grant_type={self.GRANT_TYPE}'"
            )
        self.request.client = client

        params = self.request.payload.data

        # delegation is out of scope: the issued token acts as the passport
        # subject, so there is no actor to record
        if params.get("actor_token") or params.get("actor_token_type"):
            raise InvalidRequestError(
                "Delegation is not supported; 'actor_token' must not be provided"
            )

        # a Fence access token is accepted across the whole commons rather than
        # by one named service, so honoring these would be misleading
        if params.get("audience") or params.get("resource"):
            raise InvalidTargetError(
                "This server does not issue tokens scoped to a specific "
                "'audience' or 'resource'"
            )

        subject_token = params.get("subject_token")
        if not subject_token:
            raise InvalidRequestError("Missing 'subject_token' in request")

        subject_token_type = params.get("subject_token_type")
        if not subject_token_type:
            raise InvalidRequestError("Missing 'subject_token_type' in request")

        requested_token_type = params.get("requested_token_type")
        if (
            requested_token_type
            and requested_token_type not in SUPPORTED_REQUESTED_TOKEN_TYPES
        ):
            raise InvalidRequestError(
                f"Unsupported 'requested_token_type={requested_token_type}'; this "
                f"server issues {TOKEN_TYPE_ACCESS_TOKEN}"
            )

        issuer, policy = self._get_issuer_policy(subject_token)

        if subject_token_type not in self._allowed_subject_token_types(policy):
            # don't echo the issuer's policy back to the caller
            logger.info(
                f"Rejecting token exchange: subject_token_type "
                f"'{subject_token_type}' is not allowed for issuer '{issuer}'"
            )
            raise InvalidRequestError(
                f"Unsupported 'subject_token_type={subject_token_type}'"
            )

        allowed_clients = policy.get("allowed_clients") or []
        if allowed_clients and client.client_id not in allowed_clients:
            logger.info(
                f"Rejecting token exchange: client '{client.client_id}' is not in "
                f"the allowed_clients list for issuer '{issuer}'"
            )
            raise UnauthorizedClientError(
                "This client is not authorized to exchange tokens from this issuer"
            )

        passport_claims = self._validate_passport(subject_token, issuer)

        self.subject_token = subject_token
        self.issuer_policy = policy
        self.passport_claims = passport_claims
        self.granted_scope = self._resolve_scope(client, policy)

        logger.info(
            f"Validated token exchange request from client "
            f"'{client.client_id}' for passport subject "
            f"'{passport_claims['sub']}' issued by '{issuer}'"
        )

    def create_token_response(self):
        """
        Sync the authorization described by the passport's visas, then issue a
        Fence access token for the passport subject.

        Return:
            tuple: (status code, token response body, response headers)
        """
        from fence.resources.ga4gh.passports import (
            get_or_create_gen3_user_from_iss_sub,
            sync_gen3_users_authz_from_ga4gh_passports,
        )

        subject_token = self.subject_token
        passport_claims = self.passport_claims
        issuer = passport_claims["iss"]
        subject_id = passport_claims["sub"]

        # this re-validates the passport and every visa in it against
        # GA4GH_VISA_ISSUER_ALLOWLIST, and syncs what the visas assert to
        # Arborist. the duplicated passport validation is intentional: the check
        # in validate_token_request is what keeps untrusted issuers out of this
        # code path entirely
        users_from_passport = sync_gen3_users_authz_from_ga4gh_passports(
            [subject_token]
        )
        if not users_from_passport:
            # no valid visas, or the earliest visa expiration is already too
            # close for the authz removal job to handle
            raise InvalidGrantError(
                "The subject token did not contain any usable GA4GH visas"
            )

        # identity comes from the passport's own <iss, sub>; the visas are
        # treated as authorization only. look the mapping up rather than
        # creating it, so a rejected exchange doesn't leave a user behind -- the
        # sync above already created it for every identity its visas asserted
        db_session = flask.current_app.scoped_session()
        iss_sub_pair = db_session.get(IssSubPairToUser, (issuer, subject_id))
        user = iss_sub_pair.user if iss_sub_pair else None

        require_match = self.issuer_policy.get(
            "require_passport_subject_visa_match", True
        )
        if require_match and (not user or user.username not in users_from_passport):
            logger.warning(
                f"Rejecting token exchange: the visas in the passport asserted "
                f"identities {sorted(users_from_passport.keys())}, which do not "
                f"include the passport's own subject. That subject would receive no "
                f"authorization from this exchange."
            )
            raise InvalidGrantError(
                "The subject token's visas do not describe the subject of the "
                "subject token"
            )

        if not user:
            user = get_or_create_gen3_user_from_iss_sub(issuer, subject_id)

        expires_in = self._resolve_expires_in(subject_token, passport_claims)

        token = self.generate_token(
            user=user,
            scope=" ".join(self.granted_scope),
            grant_type=self.GRANT_TYPE,
            expires_in=expires_in,
            include_refresh_token=False,
        )

        self.request.user = user
        self.save_token(token)

        logger.info(
            f"Issued token via RFC 8693 exchange: client "
            f"'{self.request.client.client_id}', user '{user.username}', passport "
            f"issuer '{issuer}', scope '{' '.join(self.granted_scope)}', "
            f"expires_in {expires_in}"
        )

        return 200, token, self.TOKEN_RESPONSE_HEADER

    def _get_issuer_policy(self, subject_token):
        """
        Read the (unverified) ``iss`` from the subject token to select the policy
        that applies to it.

        The unverified issuer is used for policy lookup ONLY. The selected
        issuer is then handed to ``_validate_passport`` as the single acceptable
        issuer, so the policy that was applied and the key that verified the
        signature are bound to each other. Doing this before any validation also
        keeps Fence from fetching keys (and therefore making outbound requests)
        for issuers it does not trust.

        Args:
            subject_token (str): the encoded subject token

        Return:
            tuple: (issuer, policy dict)
        """
        try:
            issuer = get_iss(subject_token)
        except Exception as exc:
            logger.info(f"Could not read 'iss' from subject token: {exc}")
            raise InvalidRequestError("'subject_token' is not a valid JWT")

        allowed_issuers = (
            config.get("TOKEN_EXCHANGE", {}).get("allowed_subject_token_issuers") or {}
        )
        policy = allowed_issuers.get(issuer)
        if policy is None:
            # generic error on purpose: enumerating the allowlist tells a caller
            # exactly which issuers to go get a token from
            logger.info(
                f"Rejecting token exchange: issuer '{issuer}' is not in "
                f"TOKEN_EXCHANGE.allowed_subject_token_issuers"
            )
            raise InvalidGrantError("The subject token is not acceptable")

        return issuer, policy or {}

    @staticmethod
    def _allowed_subject_token_types(policy):
        configured = policy.get("subject_token_types")
        if not configured:
            return SUPPORTED_SUBJECT_TOKEN_TYPES
        return [t for t in configured if t in SUPPORTED_SUBJECT_TOKEN_TYPES]

    @staticmethod
    def _validate_passport(subject_token, issuer):
        """
        Validate the subject token as a GA4GH passport from ``issuer``.

        Validated the same way as the passports Fence accepts at the DRS
        endpoint, except that the acceptable issuer is the single issuer whose
        policy was selected for this request.

        Args:
            subject_token (str): the encoded passport
            issuer (str): the only issuer this passport may have come from

        Return:
            dict: the validated passport claims
        """
        try:
            claims = validate_jwt(
                encoded_token=subject_token,
                attempt_refresh=True,
                require_purpose=False,
                scope={"openid"},
                issuers=[issuer],
                options={
                    "require_iat": True,
                    "require_exp": True,
                    "verify_aud": False,
                },
            )
        except Exception as exc:
            logger.info(f"Subject token failed validation: {exc}")
            raise InvalidGrantError("The subject token is not acceptable")

        if not claims.get("sub"):
            raise InvalidGrantError("The subject token is missing the 'sub' claim")

        return claims

    def _resolve_scope(self, client, policy):
        """
        Resolve the scope of the issued token: the intersection of what was
        requested, what the client is allowed, and what the issuer's policy
        allows. Never a superset of any of the three.

        Args:
            client (fence.models.Client): the authenticated client
            policy (dict): the issuer's policy

        Return:
            list: the granted scopes
        """
        client_scopes = set(client.allowed_scopes)
        policy_scopes = set(policy.get("allowed_scopes") or client_scopes)
        allowed = client_scopes & policy_scopes

        requested = self.request.payload.scope
        if requested:
            requested_scopes = set(scope_to_list(requested))
            unavailable = requested_scopes - allowed
            if unavailable:
                raise InvalidScopeError(
                    f"Requested scopes are not available for this exchange: "
                    f"{' '.join(sorted(unavailable))}"
                )
            granted = requested_scopes
        else:
            granted = allowed

        # every Fence token carries openid; Client.check_requested_scopes
        # rejects any scope set without it
        if "openid" not in granted:
            if "openid" not in allowed:
                raise InvalidScopeError(
                    "The 'openid' scope is required but is not available for "
                    "this exchange"
                )
            granted = granted | {"openid"}

        return sorted(granted)

    def _resolve_expires_in(self, subject_token, passport_claims):
        """
        Bound the issued token's lifetime by every authority behind it: the
        instance default, the issuer's cap, the passport's own expiration, and
        the earliest visa expiration seen during the sync.

        Args:
            subject_token (str): the encoded passport
            passport_claims (dict): the validated passport claims

        Return:
            int: seconds until the issued token expires
        """
        from fence.resources.ga4gh.passports import (
            get_passport_expiration_from_cache,
        )

        now = int(time.time())

        candidates = [config["ACCESS_TOKEN_EXPIRES_IN"]]

        max_lifetime = self.issuer_policy.get("max_token_lifetime")
        if max_lifetime:
            candidates.append(int(max_lifetime))

        candidates.append(int(passport_claims["exp"]) - now)

        # set by the sync to the earliest expiration among the passport's valid
        # visas, less the authz removal job frequency
        visa_expiration = get_passport_expiration_from_cache(subject_token)
        if visa_expiration:
            candidates.append(int(visa_expiration) - now)
        else:
            logger.warning(
                "Could not determine the visa expiration for an exchanged "
                "passport; falling back to the configured token lifetime"
            )

        expires_in = min(candidates)
        if expires_in <= 0:
            raise InvalidGrantError(
                "The subject token's authority expires too soon to issue a token"
            )

        logger.debug(
            f"Clamped issued token lifetime to {expires_in}s from candidates "
            f"{candidates}"
        )
        return expires_in
