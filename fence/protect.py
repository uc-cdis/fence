"""
Re-export ``authlib.flask.oauth2.current_token`` for use by external functions
requiring auth, so they can view the access token used for a request.
"""

from authlib.flask.oauth2 import ResourceProtector, current_token
from cdispyutils import auth


class FenceResourceProtector(ResourceProtector):
    """
    Define a class for protecting endpoints by requiring a valid JWT.

    See ``require_auth`` at the end of this module for usage and an example.
    """

    def __init__(self):
        pass

    def authenticate_token(self, token_string, token_type):
        """
        This function gets implemented in the parent class, but we want to
        deliberately _not_ implement it because we need to know the desired
        scope (or "audience", ``aud``, in the JWT) to validate a JWT. This
        function should never be called.
        """
        raise NotImplementedError()

    def validate_request(self, scope, method, uri, body, headers):
        """
        Validate a request.

        Calling a ``FenceResourceProtector`` instance will set
        ``current_token`` to point at the return value from this function.
        """
        return auth.validate_request_jwt(aud={scope})


#: Create a decorator function usable for protecting Flask endpoints, requiring
#: a validated access token. Functions using this decorator can then use the
#: ``current_token`` reference to get the access token in use. Example:
#:
#: .. code-block:: python
#:
#:     from fence.protect import current_token
#:
#:
#:     @blueprint.route('/some_endpoint')
#:     @require_auth('sheepdog')
#:     def some_endpoint():
#:         # do stuff
#:         projects = current_token['context']['user']['projects']
#:
require_auth = FenceResourceProtector()
