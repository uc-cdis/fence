from abc import ABC, abstractmethod

TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"
TOKEN_TYPE_GA4GH_PASSPORT = "urn:ga4gh:params:oauth:token-type:passport"

DEFAULT_REQUESTED_TOKEN_TYPES = [TOKEN_TYPE_ACCESS_TOKEN]


class ValidatedSubjectToken:
    """
    A subject token that has passed validation, and the identity it carries.

    Attributes:
        encoded_token (str): the subject token as the client sent it
        issuer (str): the verified issuer
        subject (str): the verified subject
        expires_at (int): unix time the subject token expires, if it does
        claims (dict): the verified claims, for token types that have them
    """

    def __init__(self, encoded_token, issuer, subject, expires_at=None, claims=None):
        self.encoded_token = encoded_token
        self.issuer = issuer
        self.subject = subject
        self.expires_at = expires_at
        self.claims = claims or {}


class TokenExchangeResult:
    """
    The outcome of a subject token handler's exchange-time processing.

    Attributes:
        user (fence.models.User): the user the issued token acts as
        expires_at (int): unix time the authority behind the exchange runs out.
            The grant never issues a token that outlives it.
        allowed_scopes (set): scopes the subject token can justify, if the
            handler restricts them. None means no restriction beyond the
            grant's own policy.
    """

    def __init__(self, user, expires_at=None, allowed_scopes=None):
        self.user = user
        self.expires_at = expires_at
        self.allowed_scopes = allowed_scopes


class IssuedToken:
    """
    Token issued by a requested token handler.

    Attributes:
        token (str): the issued token, returned as ``access_token`` whatever its
            type
        issued_token_type (str): token type identifier of ``token``
        token_type (str): type of token issued, such as Bearer.
        expires_in (int): lifetime of ``token`` in seconds
        scope (list): the scopes ``token`` carries
    """

    def __init__(self, token, issued_token_type, token_type, expires_in, scope):
        self.token = token
        self.issued_token_type = issued_token_type
        self.token_type = token_type
        self.expires_in = expires_in
        self.scope = scope


class SubjectTokenHandler(ABC):
    """
    Validates and interprets one or more ``subject_token_type`` values.

    The grant calls ``resolve_issuer`` and ``validate`` while validating the
    request, and ``exchange`` only once the request is accepted, so that a
    rejected request has no side effects.
    """

    @abstractmethod
    def resolve_issuer(self, subject_token):
        """
        Determine issuer of ``subject_token``.
        Args:
            subject_token (str): the subject token as the client sent it

        Return:
            str: the unverified issuer

        Raises:
            OAuth2Error: if no issuer can be read from the token
        """

    @abstractmethod
    def validate(self, subject_token, subject_token_type, issuer):
        """
        Verify ``subject_token`` and establish the identity it carries.

        Args:
            subject_token (str): the subject token as the client sent it
            subject_token_type (str): the ``subject_token_type`` the client
                sent, for handlers registered under more than one type
            issuer (str): the issuer ``resolve_issuer`` returned, already
                checked against ``TOKEN_EXCHANGE.allowed_subject_token_issuers``.
                Only accept a token that verifiably comes from this issuer.

        Return:
            ValidatedSubjectToken

        Raises:
            OAuth2Error: if the subject token is not acceptable
        """

    @abstractmethod
    def exchange(self, validated_token, issuer_policy):
        """
        Exchanges a ValidatedSubjectToken for the requested token type.

        Args:
            validated_token (ValidatedSubjectToken): from ``validate``
            issuer_policy (dict): the subject token issuer's policy,
                ``TOKEN_EXCHANGE.allowed_subject_token_issuers[issuer]``

        Return:
            TokenExchangeResult

        Raises:
            OAuth2Error: if the exchange cannot go ahead
        """


class RequestedTokenHandler(ABC):
    """
    Issues one ``requested_token_type``.
    """

    @abstractmethod
    def issue(self, user, client, scope, expires_in):
        """
        Issues the requested token as a result of the token exchange.

        Args:
            user (fence.models.User): the user the issued token acts as
            client (fence.models.Client): the authenticated client
            scope (list): the granted scopes
            expires_in (int): the issued token's lifetime in seconds, already
                clamped

        Return:
            IssuedToken
        """
