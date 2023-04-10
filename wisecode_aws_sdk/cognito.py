import boto3

def format_user(user):
    userAttributes = {att['Name']: att['Value'] for att in user['Attributes']}
    print(userAttributes)
    return {
        'id': user['Username'],
        'name': userAttributes.get('name') or userAttributes.get('email', '')
    }

def users_list(user_pool_id, cognito_client=None, region_name="us-east-2"):
  if cognito_client is None:
    cognito_client = boto3.client('cognito-idp', region_name)
  
  users = cognito_client.list_users(
    UserPoolId=user_pool_id
  )
  
  return [format_user(user) for user in users['Users']]
