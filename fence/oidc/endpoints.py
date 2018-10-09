from authlib.specs.rfc6749.errors import InvalidClientError, OAuth2Error
import authlib.specs.rfc7009
import bcrypt
import flask

from fence.errors import BlacklistingError
import fence.jwt.blacklist


class RevocationEndpoint(authlib.specs.rfc7009.RevocationEndpoint):
    """
    Inherit from ``authlib.specs.rfc7009.RevocationEndpoint`` to define how the
    server should handle requests for token revocation.
    """

    def query_token(self, token, token_type_hint, client):
        """
        Look up a token.

        Since all tokens are JWT, just return the token.
        """
        return token

    def revoke_token(self, token):
        """
        Revoke a token.
        """
        fence.jwt.blacklist.blacklist_encoded_token(token)

    def validate_authenticate_client(self):
        """
        Override parent method for client validation.
        """
        client_params = self.parse_basic_auth_header()
        if not client_params:
            flask.current_app.logger.debug(
                "validating client in revoke request:" " missing client auth header"
            )
            raise InvalidClientError(uri=self.uri)

        client_id, client_secret = client_params
        client = self.client_model.get_by_client_id(client_id)
        if not client:
            flask.current_app.logger.debug(
                "validating client in revoke request:"
                " no client with matching client id:" + " " + client_id
            )
            raise InvalidClientError(uri=self.uri)

        # The stored client secret is hashed, so hash the secret from basic
        # authorization header to check against stored hash.
        hashed = client.client_secret
        if (
            bcrypt.hashpw(client_secret.encode("utf-8"), hashed.encode("utf-8"))
            != hashed
        ):
            flask.current_app.logger.debug(
                "client secret hash does not match stored secret hash"
            )
            raise InvalidClientError(uri=self.uri)

        self._client = client

    def create_revocation_response(self):
        """
        Validate revocation request and create the response for revocation.

        Return:
            Tuple[int, dict, dict]: (status_code, body, headers)
        """
        headers = [
            ("Content-Type", "application/json"),
            ("Cache-Control", "no-store"),
            ("Pragma", "no-cache"),
        ]
        status = 204
        message = ""
        try:
            # The authorization server first validates the client credentials
            self.validate_authenticate_client()
            # then verifies whether the token was issued to the client making
            # the revocation request
            self.validate_revocation_request()
            # the authorization server invalidates the token
            self.invalidate_token(self._token)
        except OAuth2Error as error:
            status = error.status_code
            message = dict(error.get_body()).get("error_description")
            headers = error.get_headers()
            # Errors from authlib have extra methods which are supposed to be
            # used for returning error values from the authentication endpoint.
            # BlacklistingError does not have these.
        except BlacklistingError as error:
            status = error.code
            message = error.message
        finally:
            body = {"error": message} if message != "" else {}
        return (status, body, headers)
