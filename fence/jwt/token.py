import json
import time
import uuid
from enum import Enum

from authlib.common.encoding import to_unicode
from authlib.oidc.core import IDToken, CodeIDToken, ImplicitIDToken
from authlib.oidc.core.util import create_half_hash

from cdislogging import get_logger
import flask
import jwt

from fence.jwt import keys
from fence.jwt.errors import JWTSizeError
from fence.config import config

logger = get_logger(__name__)


SCOPE_DESCRIPTION = {
    "openid": "default scope",
    "user": "Know your {idp_names} basic account information and what you are authorized to access.",
    "data": "Retrieve controlled-access datasets to which you have access on your behalf.",
    "credentials": "View and update your credentials.",
    "google_link": "Allow providing your personal Google account access to data on Google.",
    "google_credentials": "Receive temporary Google credentials to access data on Google.",
    "google_service_account": "Allow registration of external Google service accounts to access data.",
    "admin": "View and update user authorizations.",
    "ga4gh_passport_v1": "Retrieve GA4GH Passports and Visas",
}


class AuthFlowTypes(Enum):
    CODE = 1
    IMPLICIT = 2


class JWTResult(object):
    """
    Just a container for the results necessary to keep track of from generating
    a JWT.
    """

    def __init__(self, token=None, kid=None, claims=None):
        self.token = token
        self.kid = kid
        self.claims = claims


class UnsignedIDToken(IDToken):
    def __init__(self, token, header=None, **kwargs):
        header = header or {}
        super(UnsignedIDToken, self).__init__(token, header, **kwargs)

    def get_signed_and_encoded_token(self, kid, private_key):
        """
        Return a signed ID token by using the private key and kid provided

        Args:
            kid (str): the key id
            private_key (str): RSA private key to sign and encode the JWT with

        Returns:
            str: UTF-8 encoded JWT ID token signed with ``private_key``
        """
        headers = {"kid": kid}
        headers.update(self.header)
        token = jwt.encode(self, private_key, headers=headers, algorithm="RS256")
        token = to_unicode(token)
        return token

    @classmethod
    def from_signed_and_encoded_token(
        cls,
        encoded_token,
        public_key=None,
        verify=True,
        client_id=None,
        issuer=None,
        max_age=None,
        nonce=None,
    ):
        """
        Return an instance of UnsignedIDToken by decoding an encoded token.

        Args:
            encoded_token (str): encoded JWT ID token signed with a private_key
            public_key (str, optional): Public key used for encoding,
                                        defaults to app's default pub key
            verify (bool, optional): Whether or not to validate the JWT
                                     and ID token.
                                     NOTE: This is TRUE by default
            client_id (str, optional): Client identifier, defaults to
                                       current client in flask context
            issuer (str, optional)
                Issuer Identifier(s) for the Issuer of the response, defaults
                to BASE_URL
            max_age (int, optional):
                max number of seconds allowed since last user AuthN
            nonce (str, optional):
                String value used to associate a Client session with an ID
                Token

        Returns:
            UnsignedIDToken: A newly created instance with claims obtained
                             from decoding the provided encoded token
        """
        # Use application defaults if not provided
        issuer = issuer or config.get("BASE_URL")
        public_key = public_key or keys.default_public_key()

        payload = jwt.decode(
            encoded_token,
            public_key,
            algorithms="RS256",
            verify=verify,
            audience=client_id,
        )
        headers = {}
        token = cls(payload, headers)

        if verify:
            token.validate()

        return token


class UnsignedCodeIDToken(UnsignedIDToken, CodeIDToken):
    pass


class UnsignedImplicitIDToken(UnsignedIDToken, ImplicitIDToken):
    pass


def issued_and_expiration_times(seconds_to_expire):
    """
    Return the times in unix time that a token is being issued and will be
    expired (the issuing time being now, and the expiration being
    ``seconds_to_expire`` seconds after that). Used for constructing JWTs

    Args:
        seconds_to_expire (int): lifetime in seconds

    Return:
        Tuple[int, int]: (issued, expired) times in unix time
    """
    iat = int(time.time())
    exp = iat + int(seconds_to_expire)
    return (iat, exp)


def generate_signed_session_token(kid, private_key, expires_in, context=None):
    """
    Generate a JWT session token from the given request, and output a UTF-8
    string of the encoded JWT signed with the private key.

    Args:
        private_key (str): RSA private key to sign and encode the JWT with
        request (oauthlib.common.Request): token request to handle
        session_started (int):
            unix time the original session token was provided

    Return:
        str: encoded JWT session token signed with ``private_key``
    """
    headers = {"kid": kid}
    iat, exp = issued_and_expiration_times(expires_in)

    issuer = config.get("BASE_URL")

    # Create context based on provided information
    if not context:
        context = {}
    if "session_started" not in context:
        context["session_started"] = iat

    claims = {
        "pur": "session",
        "aud": ["fence", issuer],
        "sub": context.get("user_id", ""),
        "iss": issuer,
        "iat": iat,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        "context": context,
    }
    logger.debug(f"issuing JWT session token: {claims}")
    token = jwt.encode(claims, private_key, headers=headers, algorithm="RS256")
    token = to_unicode(token, "UTF-8")

    # Browser may clip cookies larger than 4096 bytes
    if len(token) > 4096:
        raise JWTSizeError("JWT exceeded 4096 bytes")

    return JWTResult(token=token, kid=kid, claims=claims)


def generate_signed_id_token(
    kid,
    private_key,
    user,
    expires_in,
    client_id,
    audiences=None,
    scopes=None,
    auth_time=None,
    max_age=None,
    nonce=None,
    include_project_access=True,
    auth_flow_type=AuthFlowTypes.CODE,
    access_token=None,
    **kwargs,
):
    """
    Generate a JWT ID token, and output a UTF-8 string of the encoded JWT
    signed with the private key

    Args:
        kid (str): key id of the generated token
        private_key (str): RSA private key to sign and encode the JWT with
        user (fence.models.User): User to generate ID token for
        expires_in (int): seconds token should last
        client_id (str, optional): Client identifier
        audiences (List(str), optional):
            audiences the ID token is intended for (the aud claim).
            client_id will get appended to this.
        scopes (List[str], optional): oauth scopes for user
        auth_time (int, optional): Last time user authN'd in number of seconds
                                   from 1970-01-01T0:0:0Z as measured in
                                   UTC until the date/time
        max_age (int, optional):
            max number of seconds allowed since last user AuthN
        nonce (str, optional):
            string value used to associate a Client session with an ID Token
        include_project_access (bool, optional):
            whether to include user.project_access in the token context.user.projects
        auth_flow_type (AuthFlowTypes, optional):
            which auth flow (Auth Code or Implicit) is issuing this token
            (token validation will be different for each flow)
        access_token (string, optional):
            the access token tied to this id token; used to generate the at_hash claim

    Return:
        str: encoded JWT ID token signed with ``private_key``
    """
    token = generate_id_token(
        user,
        expires_in,
        client_id,
        include_project_access=include_project_access,
        audiences=audiences,
        scopes=scopes,
        auth_time=auth_time,
        max_age=max_age,
        nonce=nonce,
        auth_flow_type=auth_flow_type,
        access_token=access_token,
        **kwargs,
    )
    signed_token = token.get_signed_and_encoded_token(kid, private_key)
    return JWTResult(token=signed_token, kid=kid, claims=token)


def generate_signed_refresh_token(
    kid, private_key, user, expires_in, scopes, iss=None, client_id=None
):
    """
    Generate a JWT refresh token and output a UTF-8
    string of the encoded JWT signed with the private key.

    Args:
        kid (str): key id of the keypair used to generate token
        private_key (str): RSA private key to sign and encode the JWT with
        user (fence.models.User): User to generate token for
        expires_in (int): seconds until expiration
        scopes (List[str]): oauth scopes for user

    Return:
        str: encoded JWT refresh token signed with ``private_key``
    """
    headers = {"kid": kid}
    iat, exp = issued_and_expiration_times(expires_in)
    jti = str(uuid.uuid4())
    sub = str(user.id)
    if not iss:
        try:
            iss = config.get("BASE_URL")
        except RuntimeError:
            raise ValueError(
                "must provide value for `iss` (issuer) field if"
                " running outside of flask application"
            )
    claims = {
        "pur": "refresh",
        "sub": sub,
        "iss": iss,
        "aud": [iss],
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "azp": client_id or "",
        "scope": scopes,
    }

    if client_id:
        claims["aud"].append(client_id)

    logger.info("issuing JWT refresh token with id [{}] to [{}]".format(jti, sub))
    logger.debug(f"issuing JWT refresh token: {claims}")

    token = jwt.encode(claims, private_key, headers=headers, algorithm="RS256")
    token = to_unicode(token, "UTF-8")

    return JWTResult(token=token, kid=kid, claims=claims)


def generate_api_key(kid, private_key, user_id, expires_in, scopes, client_id):
    """
    Generate a JWT refresh token and output a UTF-8
    string of the encoded JWT signed with the private key.

    Args:
        kid (str): key id of the keypair used to generate token
        private_key (str): RSA private key to sign and encode the JWT with
        user_id (user id): User id to generate token for
        expires_in (int): seconds until expiration
        scopes (List[str]): oauth scopes for user_id

    Return:
        str: encoded JWT refresh token signed with ``private_key``
    """
    headers = {"kid": kid}
    iat, exp = issued_and_expiration_times(expires_in)
    jti = str(uuid.uuid4())
    sub = str(user_id)
    iss = config.get("BASE_URL")
    claims = {
        "pur": "api_key",
        "sub": sub,
        "iss": iss,
        "aud": [iss],
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "azp": client_id or "",
        "scope": scopes,
    }
    logger.info("issuing JWT API key with id [{}] to [{}]".format(jti, sub))
    logger.debug(f"issuing JWT API key: {claims}")
    token = jwt.encode(claims, private_key, headers=headers, algorithm="RS256")
    logger.debug(str(token))
    token = to_unicode(token, "UTF-8")
    return JWTResult(token=token, kid=kid, claims=claims)


def generate_signed_access_token(
    kid,
    private_key,
    user,
    expires_in,
    scopes,
    iss=None,
    forced_exp_time=None,
    client_id=None,
    linked_google_email=None,
):
    """
    Generate a JWT access token and output a UTF-8
    string of the encoded JWT signed with the private key.

    Args:
        kid (str): key id of the keypair used to generate token
        private_key (str): RSA private key to sign and encode the JWT with
        user (fence.models.User): User to generate ID token for
        expires_in (int): seconds until expiration
        scopes (List[str]): oauth scopes for user

    Return:
        str: encoded JWT access token signed with ``private_key``
    """
    headers = {"kid": kid}
    iat, exp = issued_and_expiration_times(expires_in)
    # force exp time if provided
    exp = forced_exp_time or exp
    sub = str(user.id)
    jti = str(uuid.uuid4())
    if not iss:
        try:
            iss = config.get("BASE_URL")
        except RuntimeError:
            raise ValueError(
                "must provide value for `iss` (issuer) field if"
                " running outside of flask application"
            )

    claims = {
        "pur": "access",
        "sub": sub,
        "iss": iss,
        "aud": [iss],
        "iat": iat,
        "exp": exp,
        "jti": jti,
        "scope": scopes,
        "context": {
            "user": {
                "name": user.username,
                "is_admin": user.is_admin,
                "google": {"proxy_group": user.google_proxy_group_id},
            }
        },
        "azp": client_id or "",
    }

    if client_id:
        claims["aud"].append(client_id)

    # Keep scopes in aud claim in access tokens for backwards comp....
    if scopes:
        claims["aud"] += scopes

    # only add google linkage information if provided
    if linked_google_email:
        claims["context"]["user"]["google"][
            "linked_google_account"
        ] = linked_google_email

    logger.info("issuing JWT access token with id [{}] to [{}]".format(jti, sub))
    logger.debug(f"issuing JWT access token {claims}")

    token = jwt.encode(claims, private_key, headers=headers, algorithm="RS256")
    token = to_unicode(token, "UTF-8")

    # Browser may clip cookies larger than 4096 bytes
    if len(token) > 4096:
        raise JWTSizeError("JWT exceeded 4096 bytes")

    return JWTResult(token=token, kid=kid, claims=claims)


def generate_id_token(
    user,
    expires_in,
    client_id,
    audiences=None,
    scopes=None,
    auth_time=None,
    max_age=None,
    nonce=None,
    include_project_access=True,
    auth_flow_type=AuthFlowTypes.CODE,
    access_token=None,
    **kwargs,
):
    """
    Generate an unsigned ID token object. Use `.get_signed_and_encoded_token`
    on result to retrieve a signed JWT

    Args:
        user (fence.models.User): User to generate ID token for
        expires_in (int): seconds token should last
        client_id (str, optional): Client identifier
        audiences (List(str), optional):
            audiences the ID token is intended for (the aud claim).
            client_id will get appended to this.
        scopes (List[str], optional): oauth scopes for user
        auth_time (int, optional):
            Last time user authN'd in number of seconds from 1970-01-01T0:0:0Z
            as measured in UTC until the date/time
        max_age (int, optional):
            max number of seconds allowed since last user AuthN
        nonce (str, optional):
            string value used to associate a Client session with an ID Token
        include_project_access (bool, optional):
            whether to include user.project_access in the token context.user.projects
        auth_flow_type (AuthFlowTypes, optional):
            which auth flow (Auth Code or Implicit) is issuing this token
            (token validation will be different for each flow)
        access_token (string, optional):
            the access token tied to this id token; used to generate the at_hash claim

    Returns:
        UnsignedIDToken: Unsigned ID token
    """

    iat, exp = issued_and_expiration_times(expires_in)
    issuer = config.get("BASE_URL")

    # If not provided, assume auth time is time this ID token is issued
    auth_time = auth_time or iat

    # NOTE: if the claims here are modified, be sure to update the
    # `claims_supported` field returned from the OIDC configuration endpoint
    # ``/.well-known/openid-configuration``, in
    # ``fence/blueprints/well_known.py``.
    claims = {
        "pur": "id",
        "sub": str(user.id),
        "iss": issuer,
        "iat": iat,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        "auth_time": auth_time,
        "azp": client_id,
        "scope": scopes,
        "context": {
            "user": {
                "name": user.username,
                "is_admin": user.is_admin,
                "email": user.email,
                "display_name": user.display_name,
                "phone_number": user.phone_number,
            }
        },
    }
    aud = audiences.copy() if audiences else []
    if client_id and client_id not in aud:
        aud.append(client_id)
    if issuer not in aud:
        aud.append(issuer)
    claims["aud"] = aud

    if user.tags:
        claims["context"]["user"]["tags"] = {tag.key: tag.value for tag in user.tags}

    linked_google_email = kwargs.get("linked_google_email")
    linked_google_account_exp = kwargs.get("linked_google_account_exp")
    # only add google linkage information if provided
    if linked_google_email:
        claims["context"]["user"]["google"] = {
            "linked_google_account": linked_google_email,
            "linked_google_account_exp": linked_google_account_exp,
        }

    # Only include if provided, used to associate a client session with an ID
    # token. If present in Auth Request from client, should set same val
    # in ID token
    if nonce:
        claims["nonce"] = nonce

    if include_project_access:
        claims["context"]["user"]["projects"] = dict(user.project_access)

    if access_token:
        at_hash = to_unicode(create_half_hash(access_token, "RS256"))
        claims["at_hash"] = at_hash

    logger.info(f"issuing JWT ID token: {claims}")

    token_options = {
        "iss": {"essential": True, "value": config.get("BASE_URL")},
        "nonce": {
            "essential": auth_flow_type == AuthFlowTypes.IMPLICIT,
            "value": nonce,
        },
    }
    if auth_flow_type == AuthFlowTypes.IMPLICIT:
        token = UnsignedImplicitIDToken(
            claims,
            header={"alg": "RS256"},
            options=token_options,
            params={"access_token": access_token},
        )
    else:
        if auth_flow_type != AuthFlowTypes.CODE:
            logger.error(
                "Invalid auth_flow_type passed to generate_id_token. Assuming code flow."
            )
        token = UnsignedCodeIDToken(
            claims,
            header={"alg": "RS256"},
            options=token_options,
            params={"access_token": access_token},
        )
    token.validate()

    return token
