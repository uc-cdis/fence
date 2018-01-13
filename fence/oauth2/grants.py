from authlib.specs.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant
)
from authlib.common.security import generate_token
import flask

from fence.models import AuthorizationCode


class AuthorizationCodeGrant(_AuthorizationCodeGrant):

    def create_authorization_code(self, client, user, **kwargs):
        code = AuthorizationCode(
            code=generate_token(50),
            client_id=client.client_id,
            redirect_uri=kwargs.get('redirect_uri', ''),
            scope=kwargs.get('scope', ''),
            user_id=user.id,
        )

        with flask.current_app.db.session as session:
            session.add(code)
            session.commit()

        return code.code

    def parse_authorization_code(self, code, client):
        with flask.current_app.db.session as session:
            code = (
                session.query(AuthorizationCode)
                .filter_by(code=code, client_id=client.client_id)
                .first()
            )
        if not code or code.is_expired():
            return None
        return code

    def delete_authorization_code(self, authorization_code):
        with flask.current_app.db.session as session:
            session.delete(authorization_code)
            session.commit()

    def create_access_token(self, token, client, authorization_code):
        pass
