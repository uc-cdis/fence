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
from cdislogging import get_logger

from fence.auth import get_ip_information_string
from fence.config import config
from fence.models import ClientAuthType, GrantType, IssSubPairToUser
from fence.oidc.token_exchange import (
    get_requested_token_handler,
    get_subject_token_handler,
)
from fence.oidc.token_exchange.base import (
    DEFAULT_REQUESTED_TOKEN_TYPES,
    TOKEN_TYPE_ACCESS_TOKEN,
)

logger = get_logger(__name__)

GRANT_TYPE_TOKEN_EXCHANGE = GrantType.token_exchange.value


class InvalidTargetError(OAuth2Error):
    """
    The authorization server is unable or unwilling to issue a token for the
    requested target service (the ``audience`` or ``resource`` parameter).

    https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2
    """

    error = "invalid_target"


class TokenExchangeGrant(BaseGrant, TokenEndpointMixin):
    """
    Implement the RFC 8693 token exchange grant.
    """

    GRANT_TYPE = GRANT_TYPE_TOKEN_EXCHANGE

    TOKEN_ENDPOINT_AUTH_METHODS = [
        ClientAuthType.basic.value,
        ClientAuthType.post.value,
    ]

    def validate_token_request(self):
        """
        Validate the token exchange request along with the constraints in ``config["TOKEN_EXCHANGE"]``.

        Raises:
            OAuth2Error: if the request or the subject token is not acceptable
        """
        exchange_config = config.get("TOKEN_EXCHANGE") or {}

        if not exchange_config.get("enabled"):
            raise UnsupportedGrantTypeError(self.GRANT_TYPE)

        client = self.authenticate_token_endpoint_client()
        if not client.check_grant_type(self.GRANT_TYPE):
            raise UnauthorizedClientError(
                f"The client is not authorized to use 'grant_type={self.GRANT_TYPE}'"
            )
        self.request.client = client

        params = self.request.payload.data

        if params.get("actor_token") or params.get("actor_token_type"):
            raise InvalidRequestError(
                "Delegation is not supported; 'actor_token' must not be provided"
            )

        # TODO Add task token support
        if params.get("audience") or params.get("resource"):
            raise InvalidTargetError(
                "Token exchange does not support 'audience' or 'resource'"
            )

        subject_token = params.get("subject_token")
        if not subject_token:
            raise InvalidRequestError("Missing 'subject_token' in request")

        subject_token_type = params.get("subject_token_type")
        if not subject_token_type:
            raise InvalidRequestError("Missing 'subject_token_type' in request")

        requested_token_type = (
            params.get("requested_token_type") or TOKEN_TYPE_ACCESS_TOKEN
        )

        subject_handler = get_subject_token_handler(subject_token_type)
        requested_handler = get_requested_token_handler(requested_token_type)

        issuer = subject_handler.resolve_issuer(subject_token)
        policy = self._get_issuer_policy(exchange_config, issuer)

        # don't echo the issuer's policy back to the caller
        if subject_token_type not in (policy.get("allowed_subject_token_types") or []):
            logger.info(
                f"Rejecting token exchange: subject_token_type "
                f"'{subject_token_type}' is not allowed for issuer '{issuer}'"
            )
            raise InvalidRequestError(
                f"Unsupported 'subject_token_type={subject_token_type}'"
            )

        allowed_requested_token_types = (
            policy.get("allowed_requested_token_types", DEFAULT_REQUESTED_TOKEN_TYPES)
            or []
        )
        if requested_token_type not in allowed_requested_token_types:
            logger.info(
                f"Rejecting token exchange: requested_token_type "
                f"'{requested_token_type}' is not allowed for issuer '{issuer}'"
            )
            raise InvalidRequestError(
                f"Unsupported 'requested_token_type={requested_token_type}'"
            )

        allowed_clients = policy.get("allowed_clients") or []
        if allowed_clients and client.name not in allowed_clients:
            logger.info(
                f"Rejecting token exchange: client '{client.name}' "
                f"(client_id '{client.client_id}') is not in the allowed_clients "
                f"list for issuer '{issuer}'"
            )
            raise UnauthorizedClientError(
                "This client is not authorized to exchange tokens from this issuer"
            )

        validated_subject = subject_handler.validate(
            subject_token, subject_token_type, issuer
        )

        self.subject_handler = subject_handler
        self.requested_handler = requested_handler
        self.subject_token_type = subject_token_type
        self.issuer = issuer
        self.issuer_policy = policy
        self.validated_subject = validated_subject
        self.granted_scope = self._resolve_scope(client, policy)

        logger.info(
            f"Validated token exchange request from client "
            f"'{client.client_id}' for subject '{validated_subject.subject}' "
            f"issued by '{issuer}' as '{subject_token_type}'"
        )

    def create_token_response(self):
        """
        Run the subject token handler's exchange, then issue the requested
        token for the user it resolved.

        Return:
            tuple: (status code, token response body, response headers)
        """
        client = self.request.client
        result = self.subject_handler.exchange(
            self.validated_subject, self.issuer_policy
        )

        scope = self.granted_scope
        if result.allowed_scopes is not None:
            scope = self._resolve_scope(
                client, self.issuer_policy, result.allowed_scopes
            )

        expires_in = self._resolve_expires_in(result)

        issued = self.requested_handler.issue(
            user=result.user,
            client=client,
            scope=scope,
            expires_in=expires_in,
        )

        # RFC 8693 section 2.2.1. the issued token is returned as
        # "access_token" whatever its type
        token = {
            "access_token": issued.token,
            "issued_token_type": issued.issued_token_type,
            "token_type": issued.token_type,
            "expires_in": issued.expires_in,
            "scope": " ".join(issued.scope),
        }

        self.request.user = result.user
        self.save_token(token)

        logger.info(
            f"Issued token via RFC 8693 exchange: client '{client.client_id}', "
            f"user '{result.user.username}', subject token issuer "
            f"'{self.issuer}', issued token type "
            f"'{issued.issued_token_type}', scope '{token['scope']}', "
            f"expires_in {issued.expires_in}"
        )

        self._create_login_log(result.user, issued, status_code=200)

        return 200, token, self.TOKEN_RESPONSE_HEADER

    def _create_login_log(self, user, issued, status_code):
        """
        Record the exchange as a login audit log, since it authenticates the
        user to Fence the way a login does. ``client_id`` is the client that
        made the exchange.

        Like the audit logs created after other requests, a failure to create
        this one is logged and does not fail the exchange.

        Args:
            user (fence.models.User): the user the issued token acts as
            issued (IssuedToken): the issued token
            status_code (int): the status code of the token response
        """
        issuer = self.issuer
        additional_data = [
            f"grant_type:{self.GRANT_TYPE}",
            f"subject_token_type:{self.subject_token_type}",
            f"subject_token_issuer:{issuer}",
            f"issued_token_type:{issued.issued_token_type}",
        ] + [
            f"{header}:{value}"
            for header, value in flask.request.headers
            if "X-" in header
        ]
        try:
            flask.current_app.audit_service_client.create_login_log(
                request_url=flask.request.path,
                status_code=status_code,
                username=user.username,
                sub=user.id,
                # the Fence IdP name for issuers Fence also logs users in
                # through (e.g. RAS), the issuer itself otherwise
                idp=IssSubPairToUser.ISSUER_TO_IDP.get(issuer, issuer),
                client_id=self.request.client.client_id,
                additional_data=additional_data,
                ip=get_ip_information_string(),
            )
        except Exception:
            logger.exception(
                "Unable to create audit log for token exchange! Returning the "
                "token anyway..."
            )

    @staticmethod
    def _get_issuer_policy(exchange_config, issuer):
        """
        Select the policy for the subject token's (unverified) issuer.

        The unverified issuer is used for policy lookup ONLY. The subject token
        handler is then told to accept no other issuer, so the policy that was
        applied and the key that verified the token are bound to each other.

        Args:
            exchange_config (dict): ``config["TOKEN_EXCHANGE"]``
            issuer (str): from ``SubjectTokenHandler.resolve_issuer``

        Return:
            dict: the issuer's policy
        """
        allowed_issuers = exchange_config.get("allowed_subject_token_issuers") or {}
        if issuer not in allowed_issuers:
            logger.info(
                f"Rejecting token exchange: issuer '{issuer}' is not in "
                f"TOKEN_EXCHANGE.allowed_subject_token_issuers"
            )
            raise InvalidGrantError("The subject token is not acceptable")

        return allowed_issuers[issuer] or {}

    def _resolve_scope(self, client, policy, handler_scopes=None):
        """
        Resolve the scope of the issued token: the intersection of what was
        requested, what the client is allowed, what the issuer's policy allows,
        and what the subject token handler allows if it restricted it. Never a
        superset of any of them.

        Args:
            client (fence.models.Client): the authenticated client
            policy (dict): the issuer's policy
            handler_scopes (set): ``TokenExchangeResult.allowed_scopes``, if the
                subject token handler set it

        Return:
            list: the granted scopes
        """
        client_scopes = set(client.allowed_scopes)
        policy_scopes = set(policy.get("allowed_scopes") or client_scopes)
        allowed = client_scopes & policy_scopes
        if handler_scopes is not None:
            allowed &= set(handler_scopes)

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

    def _resolve_expires_in(self, result):
        """
        Bound the issued token's lifetime by every authority behind it: the
        instance default, the issuer's cap, and the authority the subject token
        handler established.

        Args:
            result (TokenExchangeResult): from the subject token handler

        Return:
            int: seconds until the issued token expires
        """
        now = int(time.time())

        candidates = [config["ACCESS_TOKEN_EXPIRES_IN"]]

        max_lifetime = self.issuer_policy.get("max_token_lifetime")
        if max_lifetime:
            candidates.append(int(max_lifetime))

        if result.expires_at is not None:
            candidates.append(int(result.expires_at) - now)

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
