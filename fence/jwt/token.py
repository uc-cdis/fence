from datetime import datetime, timedelta
import json
import time

from authlib.common.encoding import to_unicode
from authlib.specs.oidc import CodeIDToken as AuthlibCodeIDToken
from authlib.specs.oidc import IDTokenError
import flask
import jwt
import uuid

from fence.jwt import keys


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


# Allowed scopes for user requested token and oauth2 client requested token
# TODO: this should be more discoverable and configurable
#
# Only allow web session based auth access credentials so that user
# can't create a long-lived API key using a short lived access_token
SESSION_ALLOWED_SCOPES = ['openid', 'user', 'credentials', 'data']
USER_ALLOWED_SCOPES = ['fence', 'openid', 'user', 'data']
CLIENT_ALLOWED_SCOPES = ['openid', 'user', 'data']


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
    now = datetime.now()
    iat = int(now.strftime('%s'))
    exp = int((now + timedelta(seconds=seconds_to_expire)).strftime('%s'))
    return (iat, exp)


def generate_signed_session_token(
        kid, private_key, expires_in, username=None, session_started=None,
        provider=None, redirect=None):
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
    context = {
        'session_started': session_started or iat,  # Provided or issued time
    }
    if username:
        context["username"] = username
    if provider:
        context["provider"] = provider
    if redirect:
        context["redirect"] = redirect

    claims = {
        'pur': 'session',
        'aud': ['fence'],
        'sub': username or '',
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
    return token


def generate_signed_id_token(
        kid, private_key, user, expires_in, client_id, audiences=None,
        auth_time=None, max_age=None, nonce=None):
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
        max_age=max_age, nonce=nonce
    )

    signed_token = token.get_signed_and_encoded_token(kid, private_key)
    return signed_token


def generate_signed_refresh_token(
        kid, private_key, user, expires_in, scopes):
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
    claims = {
        'pur': 'refresh',
        'aud': scopes,
        'sub': sub,
        'iss': flask.current_app.config.get('BASE_URL'),
        'iat': iat,
        'exp': exp,
        'jti': jti,
    }
    flask.current_app.logger.info(
        'issuing JWT refresh token with id [{}] to [{}]'.format(jti, sub)
    )
    flask.current_app.logger.debug(
        'issuing JWT refresh token\n' + json.dumps(claims, indent=4)
    )
    token = jwt.encode(claims, private_key, headers=headers, algorithm='RS256')
    flask.current_app.logger.debug(str(token))
    token = to_unicode(token, 'UTF-8')
    return token, claims


def generate_api_key(
        kid, private_key, user, expires_in, scopes, client_id):
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
    claims = {
        'pur': 'api_key',
        'aud': scopes,
        'sub': sub,
        'iss': flask.current_app.config.get('BASE_URL'),
        'iat': iat,
        'exp': exp,
        'jti': jti,
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
    return token, claims


def generate_signed_access_token(
        kid, private_key, user, expires_in, scopes, forced_exp_time=None):
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
    claims = {
        'pur': 'access',
        'aud': scopes,
        'sub': sub,
        'iss': flask.current_app.config.get('BASE_URL'),
        'iat': iat,
        'exp': exp,
        'jti': jti,
        'context': {
            'user': {
                'name': user.username,
                'is_admin': user.is_admin,
                'projects': dict(user.project_access),
            },
        },
    }
    flask.current_app.logger.info(
        'issuing JWT access token with id [{}] to [{}]'.format(jti, sub)
    )
    flask.current_app.logger.debug(
        'issuing JWT access token\n' + json.dumps(claims, indent=4)
    )
    token = jwt.encode(claims, private_key, headers=headers, algorithm='RS256')
    flask.current_app.logger.debug(str(token))
    token = to_unicode(token, 'UTF-8')
    return token


def generate_id_token(
        user, expires_in, client_id, audiences=None, auth_time=None,
        max_age=None, nonce=None):
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
