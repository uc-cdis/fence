"""
This blueprint defines the endpoints under ``.well-known/``, which includes:
- TODO: OIDC provider configuration
- JWK endpoint ``/jwks``
"""

import flask


blueprint = flask.Blueprint('.well-known', __name__)


@blueprint.route('/jwks', methods=['GET'])
def jwks():
    """
    Return the JWK set currently in use by fence.

    The return value from this endpoint is defined by RFC 7517.
    """
    keys = [
        keypair.public_key_to_jwk()
        for keypair in flask.current_app.keypairs
    ]
    return flask.jsonify({'keys': keys})
