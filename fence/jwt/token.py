import json
import time
import uuid

from authlib.common.encoding import to_unicode
from authlib.specs.oidc import CodeIDToken as AuthlibCodeIDToken
from authlib.specs.oidc import IDTokenError
import flask
import jwt

from fence.jwt import keys


SCOPE_DESCRIPTION = {
    'openid': 'default scope',
    'user': 'Know your {idp_names} basic account information and what you are authorized to access.',
    'data': 'Retrieve controlled-access datasets to which you have access on your behalf.',
    'credentials': 'View and update your credentials.',
    'google_credentials': 'Receive temporary Google credentials to access data on google',
    'google_service_account': 'Allow registration of external Google service accounts to access data.',
    'admin': 'View and update user authorizations.'
}


# Allowed scopes for user requested token and oauth2 client requested token
# TODO: this should be more discoverable and configurable
#
# Only allow web session based auth access credentials so that user
# can't create a long-lived API key using a short lived access_token
SESSION_ALLOWED_SCOPES = [
    'openid', 'user', 'credentials', 'data', 'admin',
    'google_credentials', 'google_service_account']

USER_ALLOWED_SCOPES = [
    'fence', 'openid', 'user', 'data', 'admin',
    'google_credentials', 'google_service_account']

CLIENT_ALLOWED_SCOPES = [
    'openid', 'user', 'data',
    'google_credentials', 'google_service_account']


class JWTResult(object):
    """
    Just a container for the results necessary to keep track of from generating
    a JWT.
    """

    def __init__(self, token=None, kid=None, claims=None):
        self.token = token
        self.kid = kid
        self.claims = claims


class UnsignedIDToken(AuthlibCodeIDToken):

    def __init__(self, token):
        super(UnsignedIDToken, self).__init__(token)

    def get_signed_and_encoded_token(self, kid, private_key):
        """
        Return a signed ID token by using the private key and kid provided

        Args:
            kid (str): the key id
            private_key (str): RSA private key to sign and encode the JWT with

        Returns:
            str: UTF-8 encoded JWT ID token signed with ``private_key``
        """
        headers = {'kid': kid}
        token = jwt.encode(
            self.token, private_key, headers=headers, algorithm='RS256'
        )
        token = to_unicode(token)
        return token

    def validate_auth_time(self, max_age):
        """
        Validate that the token isn't too old (in other words, the
        time since user last authN'd is less than `max_age`)

        Args:
            max_age (int): max number of seconds allowed since last user AuthN

        Raises:
            IDTokenError: Either max_age is provided and there's no auth_time
                          field, or the token is too old
        """
        # Patch authlib to actually check max_age against auth_time and handle
        super(UnsignedIDToken, self).validate_auth_time(max_age)
        if max_age:
            age = int(time.time()) - self.auth_time
            if max_age < age:
                # FIXME: OP MUST attempt to actively re-authenticate the
                # End-User
                raise IDTokenError(
                    'too old. age since auth_time is greater than max_age'
                )

    def validate(self, client_id, issuer=None, max_age=None, nonce=None):
        """
        Validate the current token. Exceptions are thrown if there are
        issues

        Args:
            client_id (Optional[str]):
                Client identifier, defaults to current client in flask's
                context
            issuer (Optional[str]):
                Issuer Identifier for the Issuer of the response, Defaults to
                this app's BASE_URL
            max_age (Optional[int]):
                max number of seconds allowed since last user AuthN
            nonce (Optional[str]):
                string value used to associate a Client session with an ID
                Token
        """
        issuer = issuer or flask.current_app.config.get('BASE_URL')
        now = time.time()

        super(UnsignedIDToken, self).validate(
            issuer=issuer, client_id=client_id, max_age=max_age, nonce=nonce,
            now=now
        )

    @classmethod
    def from_signed_and_encoded_token(
            cls, encoded_token, public_key=None, verify=True,
            client_id=None, issuer=None, max_age=None, nonce=None):
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
        issuer = issuer or flask.current_app.config.get('BASE_URL')
        public_key = public_key or keys.default_public_key()

        token = jwt.decode(
            encoded_token, public_key, algorithms='RS256', verify=verify,
            audience=client_id
        )

        token = cls(token)

        if verify:
            token.validate(
                client_id=client_id, issuer=issuer, max_age=max_age,
                nonce=nonce
            )

        return token


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


def generate_signed_session_token(
        kid, private_key, expires_in, context=None):
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
    headers = {'kid': kid}
    iat, exp = issued_and_expiration_times(expires_in)

    issuer = flask.current_app.config.get('BASE_URL')

    # Create context based on provided information
    if not context:
        context = {}
    if 'session_started' not in context:
        context['session_started'] = iat

    claims = {
        'pur': 'session',
        'aud': ['fence'],
        'sub': context.get('user_id', ''),
        'iss': issuer,
        'iat': iat,
        'exp': exp,
        'jti': str(uuid.uuid4()),
        'context': context,
    }
    flask.current_app.logger.debug(
        'issuing JWT session token\n' + json.dumps(claims, indent=4)
    )
    token = jwt.encode(claims, private_key, headers=headers, algorithm='RS256')
    token = to_unicode(token, 'UTF-8')
    return JWTResult(token=token, kid=kid, claims=claims)


def generate_signed_id_token(
        kid, private_key, user, expires_in, client_id, audiences=None,
        auth_time=None, max_age=None, nonce=None, **kwargs):
    """
    Generate a JWT ID token, and output a UTF-8 string of the encoded JWT
    signed with the private key

    Args:
        kid (str): key id of the generated token
        private_key (str): RSA private key to sign and encode the JWT with
        user (fence.models.User): User to generate ID token for
        expires_in (int): seconds token should last
        client_id (str, optional): Client identifier
        audiences (List(str), optional): Description
        auth_time (int, optional): Last time user authN'd in number of seconds
                                   from 1970-01-01T0:0:0Z as measured in
                                   UTC until the date/time
        max_age (int, optional):
            max number of seconds allowed since last user AuthN
        nonce (str, optional):
            string value used to associate a Client session with an ID Token

    Return:
        str: encoded JWT ID token signed with ``private_key``
    """
    token = generate_id_token(
        user, expires_in, client_id, audiences=audiences, auth_time=auth_time,
        max_age=max_age, nonce=nonce, **kwargs
    )
    signed_token = token.get_signed_and_encoded_token(kid, private_key)
    return JWTResult(token=signed_token, kid=kid, claims=token.token)


def generate_signed_refresh_token(
        kid, private_key, user, expires_in, scopes, iss=None, client_id=None):
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
    headers = {'kid': kid}
    iat, exp = issued_and_expiration_times(expires_in)
    jti = str(uuid.uuid4())
    sub = str(user.id)
    if not iss:
        try:
            iss = flask.current_app.config.get('BASE_URL')
        except RuntimeError:
            raise ValueError(
                'must provide value for `iss` (issuer) field if'
                ' running outside of flask application'
            )
    claims = {
        'pur': 'refresh',
        'aud': scopes,
        'sub': sub,
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'azp': client_id or ''
    }

    if flask.current_app:
        flask.current_app.logger.info(
            'issuing JWT refresh token with id [{}] to [{}]'.format(jti, sub)
        )
        flask.current_app.logger.debug(
            'issuing JWT refresh token\n' + json.dumps(claims, indent=4)
        )

    token = jwt.encode(claims, private_key, headers=headers, algorithm='RS256')
    token = to_unicode(token, 'UTF-8')

    return JWTResult(token=token, kid=kid, claims=claims)


def generate_api_key(
        kid, private_key, user_id, expires_in, scopes, client_id):
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
    headers = {'kid': kid}
    iat, exp = issued_and_expiration_times(expires_in)
    jti = str(uuid.uuid4())
    sub = str(user_id)
    claims = {
        'pur': 'api_key',
        'aud': scopes,
        'sub': sub,
        'iss': flask.current_app.config.get('BASE_URL'),
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'azp': client_id or ''
    }
    flask.current_app.logger.info(
        'issuing JWT API key with id [{}] to [{}]'.format(jti, sub)
    )
    flask.current_app.logger.debug(
        'issuing JWT API key\n' + json.dumps(claims, indent=4)
    )
    token = jwt.encode(claims, private_key, headers=headers, algorithm='RS256')
    flask.current_app.logger.debug(str(token))
    token = to_unicode(token, 'UTF-8')
    return JWTResult(token=token, kid=kid, claims=claims)


def generate_signed_access_token(
        kid, private_key, user, expires_in, scopes, iss=None,
        forced_exp_time=None, client_id=None, linked_google_email=None):
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
    headers = {'kid': kid}
    iat, exp = issued_and_expiration_times(expires_in)
    # force exp time if provided
    exp = forced_exp_time or exp
    sub = str(user.id)
    jti = str(uuid.uuid4())
    if not iss:
        try:
            iss = flask.current_app.config.get('BASE_URL')
        except RuntimeError:
            raise ValueError(
                'must provide value for `iss` (issuer) field if'
                ' running outside of flask application'
            )
    policies = [policy.id for policy in user.policies]

    claims = {
        'pur': 'access',
        'aud': scopes,
        'sub': sub,
        'iss': iss,
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'context': {
            'user': {
                'name': user.username,
                'is_admin': user.is_admin,
                'projects': dict(user.project_access),
                'policies': policies,
                'google': {
                    'proxy_group': user.google_proxy_group_id,
                }
            },
        },
        'azp': client_id or ''
    }

    # only add google linkage information if provided
    if linked_google_email:
        claims['context']['user']['google']['linked_google_account'] = (
            linked_google_email
        )

    if flask.current_app:
        flask.current_app.logger.info(
            'issuing JWT access token with id [{}] to [{}]'.format(jti, sub)
        )
        flask.current_app.logger.debug(
            'issuing JWT access token\n' + json.dumps(claims, indent=4)
        )

    token = jwt.encode(claims, private_key, headers=headers, algorithm='RS256')
    token = to_unicode(token, 'UTF-8')
    return JWTResult(token=token, kid=kid, claims=claims)


def generate_id_token(
        user, expires_in, client_id, audiences=None, auth_time=None,
        max_age=None, nonce=None, **kwargs):
    """
    Generate an unsigned ID token object. Use `.get_signed_and_encoded_token`
    on result to retrieve a signed JWT

    Args:
        user (fence.models.User): User to generate ID token for
        expires_in (int): seconds token should last
        client_id (str, optional): Client identifier
        audiences (List(str), optional): Description
        auth_time (int, optional):
            Last time user authN'd in number of seconds from 1970-01-01T0:0:0Z
            as measured in UTC until the date/time
        max_age (int, optional):
            max number of seconds allowed since last user AuthN
        nonce (str, optional):
            string value used to associate a Client session with an ID Token

    Returns:
        UnsignedIDToken: Unsigned ID token
    """
    iat, exp = issued_and_expiration_times(expires_in)
    issuer = flask.current_app.config.get('BASE_URL')

    # include client_id if not already in audiences
    if audiences:
        if client_id not in audiences:
            audiences.append(client_id)
    else:
        audiences = [client_id]

    # If not provided, assume auth time is time this ID token is issued
    auth_time = auth_time or iat
    policies = [policy.id for policy in user.policies]

    # NOTE: if the claims here are modified, be sure to update the
    # `claims_supported` field returned from the OIDC configuration endpoint
    # ``/.well-known/openid-configuration``, in
    # ``fence/blueprints/well_known.py``.
    claims = {
        'pur': 'id',
        'aud': audiences,
        'sub': str(user.id),
        'iss': issuer,
        'iat': iat,
        'exp': exp,
        'jti': str(uuid.uuid4()),
        'auth_time': auth_time,
        'azp': client_id,
        'context': {
            'user': {
                'name': user.username,
                'is_admin': user.is_admin,
                'projects': dict(user.project_access),
                'policies': policies,
                'email': user.email,
                'display_name': user.display_name,
                'phone_number': user.phone_number
            },
        },
    }
    if user.tags:
        claims['context']['user']['tags'] = {
            tag.key: tag.value for tag in user.tags
        }

    linked_google_email = kwargs.get('linked_google_email')
    linked_google_account_exp = kwargs.get('linked_google_account_exp')
    # only add google linkage information if provided
    if linked_google_email:
        claims['context']['user']['google'] = {
            'linked_google_account': linked_google_email,
            'linked_google_account_exp': linked_google_account_exp,
        }

    # Only include if provided, used to associate a client session with an ID
    # token. If present in Auth Request from client, should set same val
    # in ID token
    if nonce:
        claims['nonce'] = nonce

    flask.current_app.logger.info(
        'issuing JWT ID token\n' + json.dumps(claims, indent=4)
    )

    token = UnsignedIDToken(claims)
    token.validate(
        issuer=flask.current_app.config.get('BASE_URL'),
        client_id=client_id, max_age=max_age, nonce=nonce)

    return token
