from datetime import datetime, timedelta
import json
import time

from authlib.specs.oidc import CodeIDToken as AuthlibCodeIDToken
from authlib.specs.oidc import IDTokenError
from authlib.common.encoding import to_unicode
from cdispyutils import auth
import flask
import jwt
import uuid

from fence.jwt import blacklist
from fence.jwt import errors
from fence.jwt import keys
from fence.jwt.blacklist import BlacklistedToken


class UnsignedIDToken(AuthlibCodeIDToken):
    # TODO When we upgrade to authlib v0.4, `validate_exp` can be removed
    # There was a bug in `validate_exp` in v0.3 that needed to be patched

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
        token = jwt.encode(self.token, private_key, headers=headers, algorithm='RS256')
        token = to_unicode(token)
        return token

    def validate_exp(self, now):
        """
        Validate that the token hasn't expired

        Args:
            now (int): number of seconds from 1970-01-01T0:0:0Z as measured in
                       UTC until the date/time

        Raises:
            IDTokenError: token has expired
        """
        # Patch bug in authlib where error is raised when exp is in the future
        if 'exp' not in self.token:
            raise IDTokenError('exp is required')
        if now and self.exp < now:
            raise IDTokenError('exp is expired')

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
                # FIXME: OP MUST attempt to actively re-authenticate the End-User
                raise IDTokenError('too old. age since auth_time is greater than max_age')

    def validate(self, client_id, issuer=None, max_age=None, nonce=None):
        """
        Validate the current token. Exceptions are thrown if there are
        issues

        Args:
            client_id (str, optional): Client identifier, defaults to
                                        current client in flask's context
            issuer (str, optional): Issuer Identifier for the Issuer of the response,
                                          Defaults to this app's HOST_NAME
            max_age (int, optional): max number of seconds allowed since last user AuthN
            nonce (str, optional): String value used to associate a Client session with an ID Token
        """
        issuer = issuer or flask.current_app.config.get('HOST_NAME')
        now = time.time()

        super(UnsignedIDToken, self).validate(
            issuer=issuer, client_id=client_id, max_age=max_age, nonce=nonce, now=now)

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
            issuer (str, optional): Issuer Identifier(s) for the Issuer of the response,
                                          defaults to HOST_NAME
            max_age (int, optional): max number of seconds allowed since last user AuthN
            nonce (str, optional): String value used to associate a Client session with an ID Token

        Returns:
            UnsignedIDToken: A newly created instance with claims obtained
                             from decoding the provided encoded token
        """
        # Use application defaults if not provided
        issuer = issuer or flask.current_app.config.get('HOST_NAME')
        public_key = public_key or keys.default_public_key()

        token = jwt.decode(
            encoded_token, public_key, algorithms='RS256', verify=verify, audience=client_id)

        token = cls(token)

        if verify:
            token.validate(
                client_id=client_id, issuer=issuer, max_age=max_age,
                nonce=nonce)

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
    now = datetime.now()
    iat = int(now.strftime('%s'))
    exp = int((now + timedelta(seconds=seconds_to_expire)).strftime('%s'))
    return (iat, exp)


def generate_id_token(user, expires_in, client_id,
                      audiences=None, auth_time=None, max_age=None, nonce=None):
    """
    Generate an unsigned ID token object. Use `.get_signed_and_encoded_token` on result
    to retrieve a signed JWT

    Args:
        user (fence.models.User): User to generate ID token for
        expires_in (int): seconds token should last
        client_id (str, optional): Client identifier
        audiences (List(str), optional): Description
        auth_time (int, optional): Last time user authN'd in number of seconds
                                   from 1970-01-01T0:0:0Z as measured in
                                   UTC until the date/time
        max_age (int, optional): max number of seconds allowed since last user AuthN
        nonce (str, optional): String value used to associate a Client session with an ID Token

    Returns:
        UnsignedIDToken: Unsigned ID token
    """
    iat, exp = issued_and_expiration_times(expires_in)
    issuer = flask.current_app.config.get('HOST_NAME')

    # include client_id if not already in audiences
    if audiences:
        if client_id not in audiences:
            audiences.append(client_id)
    else:
        audiences = [client_id]

    # If not provided, assume auth time is time this ID token is issued
    auth_time = auth_time or iat

    claims = {
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
            },
        },
    }

    # Only include if provided, used to associate a client session with an ID
    # token. If present in Auth Request from client, should set same val
    # in ID token
    if nonce:
        claims['nonce'] = nonce

    flask.current_app.logger.info(
        'issuing JWT ID token\n' + json.dumps(claims, indent=4)
    )

    token =  UnsignedIDToken(claims)
    token.validate(
        issuer=flask.current_app.config.get('HOST_NAME'),
        client_id=client_id, max_age=max_age, nonce=nonce)

    return token


def generate_signed_id_token(kid, private_key, user, expires_in, client_id,
                             audiences=None, auth_time=None, max_age=None, nonce=None):
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
        max_age (int, optional): max number of seconds allowed since last user AuthN
        nonce (str, optional): String value used to associate a Client session with an ID Token

    Return:
        str: encoded JWT ID token signed with ``private_key``
    """
    token = generate_id_token(
        user, expires_in, client_id,
        audiences=audiences, auth_time=auth_time, max_age=max_age, nonce=nonce)

    signed_token = token.get_signed_and_encoded_token(kid, private_key)
    return signed_token


def generate_signed_refresh_token(kid, private_key, user, expires_in, scopes):
    """
    Generate a JWT refresh token and output a UTF-8
    string of the encoded JWT signed with the private key.

    Args:
        kid (str): key id of the generated token
        private_key (str): RSA private key to sign and encode the JWT with
        user (fence.models.User): User to generate ID token for
        expires_in (int): seconds token should last
        scopes (List[str]): oauth scopes for user

    Return:
        str: encoded JWT refresh token signed with ``private_key``
    """
    headers = {'kid': kid}
    iat, exp = issued_and_expiration_times(expires_in)
    claims = {
        'aud': ['refresh'],
        'sub': str(user.id),
        'iss': flask.current_app.config.get('HOST_NAME'),
        'iat': iat,
        'exp': exp,
        'jti': str(uuid.uuid4()),
        'access_aud': scopes,
    }
    flask.current_app.logger.info(
        'issuing JWT refresh token\n' + json.dumps(claims, indent=4)
    )
    token = jwt.encode(claims, private_key, headers=headers, algorithm='RS256')
    flask.current_app.logger.debug(str(token))
    token = to_unicode(token, 'UTF-8')
    return token


def generate_signed_access_token(kid, private_key, user, expires_in, scopes):
    """
    Generate a JWT access token and output a UTF-8
    string of the encoded JWT signed with the private key.

    Args:
        kid (str): key id of the generated token
        private_key (str): RSA private key to sign and encode the JWT with
        user (fence.models.User): User to generate ID token for
        expires_in (int): seconds token should last
        scopes (List[str]): oauth scopes for user

    Return:
        str: encoded JWT access token signed with ``private_key``
    """
    headers = {'kid': kid}
    iat, exp = issued_and_expiration_times(expires_in)
    claims = {
        'aud': scopes + ['access'],
        'sub': str(user.id),
        'iss': flask.current_app.config.get('HOST_NAME'),
        'iat': iat,
        'exp': exp,
        'jti': str(uuid.uuid4()),
    }
    flask.current_app.logger.info(
        'issuing JWT access token\n' + json.dumps(claims, indent=4)
    )
    token = jwt.encode(claims, private_key, headers=headers, algorithm='RS256')
    flask.current_app.logger.debug(str(token))
    token = to_unicode(token, 'UTF-8')
    return token


def validate_refresh_token(refresh_token):
    """
    Validate token existing

    Args:
        refresh_token (str): encoded JWT refresh token

    Returns:
        Token: Decoded refresh token

    Raises:
        errors.JWTError: Invalid token
    """
    if not refresh_token:
        raise errors.JWTError('No token provided.')

    # Must contain just a `'refresh'` audience for a refresh token.
    decoded_jwt = auth.validate_jwt(
        encoded_token=refresh_token,
        public_key=keys.default_public_key(),
        aud={'refresh'},
        iss=flask.current_app.config['HOST_NAME'],
    )

    # Validate jti and make sure refresh token is not blacklisted.
    jti = decoded_jwt.get('jti')
    if not jti:
        errors.JWTError('Token missing jti claim.')
    with flask.current_app.db.session as session:
        if session.query(BlacklistedToken).filter_by(jti=jti).first():
            raise errors.JWTError('Token is blacklisted.')

    return decoded_jwt


def revoke_token(encoded_token):
    """
    Revoke a refresh token.

    If the operation is successful, return an empty response with a 204 status
    code. Otherwise, return error message in JSON with a 400 code.

    Return:
        Tuple[str, int]: JSON response and status code
    """

    # Try to blacklist the token; see possible exceptions raised in
    # ``blacklist_encoded_token``.
    try:
        blacklist.blacklist_encoded_token(encoded_token)
    except jwt.InvalidTokenError:
        raise errors.JWTError('invalid token', 400)
    except KeyError as e:
        msg = 'token missing claim: {}'.format(str(e))
        raise errors.JWTError(msg, 400)
    except ValueError as e:
        raise errors.JWTError(str(e), 400)
