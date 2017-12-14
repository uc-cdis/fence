from ...jwt import token


def create_refresh_token(user, keypair, expires_in):
    return token.generate_signed_refresh_token(keypair.kid, keypair.private_key, user, expires_in)


def create_access_token(user, keypair, scope, expires_in):
    return token.generate_signed_access_token(keypair.kid, keypair.private_key, user, expires_in, scope)


def list_refresh_tokens(user):
    result = []
    tokens = token.list_tokens(user)
    for tok in tokens:
        result.append(tok.refresh_token)
    return result


def revoke_refresh_token(encoded_token):
    return token.revoke_token(encoded_token)
