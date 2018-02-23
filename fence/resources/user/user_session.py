"""
Sessions by using a JWT.

Implementation Details:

Every request where the Flask session is modified internally (e.g. by a user
logging in) a new JWT is created and stored in a cookie. Additionally, if the
user is successfully logged in, an access token is stored in a cookie as well.

The session timeout relies on the expiration functionality of the JWT, as after
each request, the expiration gets extended by SESSION_TIMEOUT. Note that the
cookie expiration is also used to mirror the JWT timeout, though we are not
solely relying on the browser or application to ignore the expired cookie.

While the session is NOT expired, a `session_started` time is kept between the
issuing of new JWTs with new expiration times. This absolute beginning of the
session is used to calculate if the user has extended their session past the
SESSION_LIFETIME. If that happens, we expire the session.

During a valid session where a user is logged in, if there is no access token,
a new one will be generated with expiration defined by ACCESS_TOKEN_LIFETIME (
in other words, the session token can refresh the access token).

Before a session is opened with user information, an expiration check occurs.
"""

from flask.sessions import SessionInterface
from flask.sessions import SessionMixin
from flask import current_app
from flask import g
from datetime import datetime
import pytz
import time

from fence.user import get_current_user
from fence.errors import Unauthorized
from fence.jwt.keys import default_public_key
from fence.jwt.token import (
    SESSION_ALLOWED_SCOPES,
    generate_signed_access_token,
    generate_signed_session_token,
)
from fence.jwt.validate import validate_jwt
from fence.jwt.validate import JWTError
from fence.resources.storage.cdis_jwt import create_session_token


class UserSession(SessionMixin):
    def __init__(self, session_token):
        self._encoded_token = session_token

        if session_token:
            try:
                jwt_info = validate_jwt(
                    session_token,
                    public_key=default_public_key(),
                    aud={'fence'},
                )
            except JWTError:
                # if session token is invalid, create a new
                # empty one silently
                jwt_info = self._get_initial_session_token()
        else:
            jwt_info = self._get_initial_session_token()

        self.session_token = jwt_info

        self.modified = False
        super(UserSession, self).__init__()

    def _get_initial_session_token(self):
        keypair = current_app.keypairs[0]
        session_token = generate_signed_session_token(
            kid=keypair.kid,
            private_key=keypair.private_key,
            expires_in=current_app.config.get('SESSION_TIMEOUT').seconds,
        )
        self._encoded_token = session_token
        initial_token = validate_jwt(
            session_token,
            aud={'fence'},
            purpose='session',
            public_key=default_public_key(),
        )
        return initial_token

    def create_initial_token(self):
        initial_token = self._get_initial_session_token()
        self.session_token = initial_token

    def get_updated_token(self, app):
        if self._encoded_token:
            timeout = app.config.get('SESSION_TIMEOUT')

            # Create a new token by passing in fields from the current
            # token. If `session_started` is None, it will be defaulted
            # to the issue time for the JWT and passed into future tokens
            # to keep track of the overall lifetime of the session
            token = create_session_token(
                current_app.keypairs[0],
                timeout.seconds,
                self.session_token['context']
            )
            self._encoded_token = token

        return self._encoded_token

    def get(self, key, *args):
        """
        get a value from session json
        """
        return self.session_token["context"].get(key, *args)

    def pop(self, key):
        return self.session_token['context'].pop(key)

    def clear(self):
        """
        clear current session
        """
        self._encoded_token = None
        self.session_token = {"context": {}}

    def clear_if_expired(self, app):
        if self._encoded_token:
            lifetime = app.config.get('SESSION_LIFETIME')

            now = int(time.time())
            is_expired = (self.session_token['exp'] <= now)
            end_of_life = (
                self.session_token['context']['session_started']
                + lifetime.seconds
            )

            lifetime_over = (end_of_life <= now)
            if is_expired or lifetime_over:
                self.clear()
        else:
            # if there's no current token set, clear data to be sure
            self.clear()

    def __contains__(self, key):
        return key in self.session_token['context']

    def __getitem__(self, key):
        return self.session_token["context"][key]

    def __setitem__(self, key, value):
        # If token doesn't exists, create the first session token when
        # data in the session is attempting to be set
        if not self._encoded_token:
            self.create_initial_token()

        self.session_token["context"][key] = value
        self.modified = True

    def __delitem__(self, key):
        del self.session_token["context"][key]
        self.modified = True

    def __iter__(self):
        for key in self.session_token:
            yield key

    def __len__(self):
        return len(self.session_token)

    def pop(self, key):
        return self.session_token['context'].pop(key)


class UserSessionInterface(SessionInterface):

    def __init__(self):
        super(UserSessionInterface, self).__init__()

    def open_session(self, app, request):
        jwt = request.cookies.get(app.session_cookie_name)
        g.access_token = (
            request.cookies.get(app.config['ACCESS_TOKEN_COOKIE_NAME'], None)
        )
        session = UserSession(jwt)

        # NOTE: If we did the expiration check in save_session
        # then an expired token could be used for a single request
        # (on open_session) before it's invalidated for being expired
        session.clear_if_expired(app)

        return session

    def get_expiration_time(self, app, session):
        token_expiration = session.session_token["exp"]
        timeout = datetime.fromtimestamp(token_expiration, pytz.utc)
        return timeout

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        token = session.get_updated_token(app)
        if token:
            response.set_cookie(
                app.session_cookie_name, token,
                expires=self.get_expiration_time(app, session),
                httponly=True, domain=domain)
            # try to get user, execption means they're not logged in
            try:
                user = get_current_user()
            except Unauthorized:
                user = None

            if user and not g.access_token:
                _create_access_token_cookie(app, response, user)
        else:
            # If there isn't a session token, we should set
            # the cookies to nothing and expire them immediately.
            #
            # This supports the case where the user logs out partially
            # into their timeout window and the session gets cleared. We
            # also need to clear the cookies in this case.
            #
            # NOTE: The session token will STILL BE VALID until its
            #       expiration it just won't be stored in the cookie
            #       anymore
            response.set_cookie(
                app.session_cookie_name,
                expires=0,
                httponly=True, domain=domain)
            response.set_cookie(
                app.config['ACCESS_TOKEN_COOKIE_NAME'],
                expires=0,
                httponly=True, domain=domain)


def _clear_session_if_expired(app, session):
    lifetime = app.config.get('SESSION_LIFETIME')

    now = int(time.time())
    is_expired = (session.session_token["exp"] <= now)
    end_of_life = session["session_started"] + lifetime.seconds

    lifetime_over = (end_of_life <= now)
    if is_expired or lifetime_over:
        session.clear()


def _create_access_token_cookie(app, response, user):
    keypair = app.keypairs[0]
    scopes = SESSION_ALLOWED_SCOPES

    now = datetime.now()
    expiration = int(
        (now + app.config.get('ACCESS_TOKEN_LIFETIME')).strftime('%s')
    )
    timeout = datetime.fromtimestamp(expiration, pytz.utc)

    access_token = generate_signed_access_token(
        keypair.kid, keypair.private_key, user,
        app.config.get('ACCESS_TOKEN_LIFETIME').seconds, scopes,
        forced_exp_time=expiration
    )

    domain = app.session_interface.get_cookie_domain(app)
    response.set_cookie(
        app.config['ACCESS_TOKEN_COOKIE_NAME'], access_token,
        expires=timeout,
        httponly=True, domain=domain
    )

    return response
