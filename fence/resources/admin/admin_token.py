from fence.resources.user.user_session import create_long_access_token

def get_long_lived_token(current_app, current_user):
    return create_long_access_token(current_app, current_user)
