from fence.resources.user.user_session import create_long_access_token
import fence.resources.user as us
import jwt


def get_long_lived_token(current_app, current_session,  token):
    decoded_token = jwt.decode(token, verify=False)
    user = us.get_user(current_session, decoded_token['context']['user']['name'])
    return create_long_access_token(current_app, user)
