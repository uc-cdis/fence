from ...jwt import token


def create_refresh_token(user, keypair, expires_in, scopes):
    return token.generate_signed_refresh_token(keypair.kid, keypair.private_key, user, expires_in, scopes)


def create_access_token(user, keypair, expires_in, scopes):
    return token.generate_signed_access_token(keypair.kid, keypair.private_key, user, expires_in, scopes)


def list_refresh_tokens(user):
    result = []
    tokens = token.list_tokens(user)
    for tok in tokens:
        result.append(tok.refresh_token)
    return result


def revoke_refresh_token(encoded_token):
    return token.revoke_token(encoded_token)
