"""
Sessions by using a JWT.

Implementation Details:

Every request, a new JWT is created and stored in a cookie.
The session timeout relies on the expiration functionality of the JWT, as
after each request, the expiration gets extended by SESSION_TIMEOUT.

While the session is NOT expired, a `session_started` time is kept between
the issuing of new JWTs with new expiration times. This absolute
beginning of the session is used to calculate if the user has
extended their session past the SESSION_LIFETIME. If that happens,
we expire the session.

Before a session is opened with user information, an expiration check occurs.
"""


from flask.sessions import SessionInterface
from flask.sessions import SessionMixin
from flask import current_app
from datetime import datetime

from cdispyutils.auth.jwt_validation import validate_jwt
from fence.jwt.keys import default_public_key

from fence.resources.storage.cdis_jwt import create_session_token


class UserSession(SessionMixin):
    def __init__(self, jwt):
        self._encoded_jwt = jwt

        if jwt:
            jwt_info = validate_jwt(
                jwt,
                public_key=default_public_key(),
                aud={"session"},
                iss=current_app.config["HOST_NAME"]
            )
        else:
            jwt_info = {"context": {}}

        self.jwt = jwt_info

        self.modified = False
        super(UserSession, self).__init__()

    def create_initial_token(self):
        jwt = create_session_token(
            current_app.keypairs[0],
            current_app.config.get('SESSION_TIMEOUT').seconds
        )
        self._encoded_jwt = jwt
        self.jwt = validate_jwt(
            jwt,
            public_key=default_public_key(),
            aud={"session"},
            iss=current_app.config["HOST_NAME"]
        )

    def get_updated_token(self, app):
        if self._encoded_jwt:
            timeout = app.config.get('SESSION_TIMEOUT')

            token = create_session_token(
                current_app.keypairs[0],
                timeout.seconds,
                session_started=self.get("session_started", None),
                username=self.get("username", None),
                provider=self.get("provider", None),
                redirect=self.get("redirect", None)
            )
            self._encoded_jwt = token

        return self._encoded_jwt

    def get(self, key, *args):
        """
        get a value from session json
        """
        return self.jwt["context"].get(key, *args)

    def clear(self):
        """
        clear current session
        """
        self._encoded_jwt = None
        self.jwt = {"context": {}}

    def clear_if_expired(self, app):
        if self._encoded_jwt:
            lifetime = app.config.get('SESSION_LIFETIME')

            now = int(datetime.utcnow().strftime('%s'))
            is_expired = (self.jwt["exp"] <= now)
            end_of_life = self.jwt["context"]["session_started"] + lifetime.seconds

            lifetime_over = (end_of_life <= now)
            if is_expired or lifetime_over:
                self.clear()
        else:
            # if there's no current token set, clear data to be sure
            self.clear()

    def __getitem__(self, key):
        return self.jwt["context"][key]

    def __setitem__(self, key, value):
        # If token doesn't exists, create the first session token when
        # data in the session is attempting to be set
        if not self._encoded_jwt:
            self.create_initial_token()

        self.jwt["context"][key] = value
        self.modified = True

    def __delitem__(self, key):
        del self.jwt["context"][key]
        self.modified = True

    def __iter__(self):
        for key in self.jwt:
            yield key

    def __len__(self):
        return len(self.jwt)


class UserSessionInterface(SessionInterface):

    def __init__(self):
        super(UserSessionInterface, self).__init__()

    def open_session(self, app, request):
        jwt = request.cookies.get(app.session_cookie_name)
        session = UserSession(jwt)

        # NOTE: If we did the expiration check in save_session
        # then an expired token could be used for a single request
        # (on open_session) before it's invalidated for being expired
        session.clear_if_expired(app)

        return session

    def get_expiration_time(self, app, session):
        timeout = datetime.utcnow() + app.config.get('SESSION_TIMEOUT')
        return timeout

    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        token = session.get_updated_token(app)
        if token:
            response.set_cookie(
                app.session_cookie_name, token,
                expires=self.get_expiration_time(app, session),
                httponly=True, domain=domain)


def _clear_session_if_expired(app, session):
    lifetime = app.config.get('SESSION_LIFETIME')

    now = int(datetime.utcnow().strftime('%s'))
    is_expired = (session.jwt["exp"] <= now)
    end_of_life = session["session_started"] + lifetime.seconds

    lifetime_over = (end_of_life <= now)
    if is_expired or lifetime_over:
        session.clear()
