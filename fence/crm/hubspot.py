import flask


#TODO ADD hubspot API

def get_user_info(hubspot_id):
	data = {}
	data["first_name"] = "Luca"
	data["last_name"] = "Graglia"
	return data

def update_user_info(first_name, last_name, institution):
	#TODO call hubspot API and return id
	return 1

# def register_arborist_user(user, policies=None):
#     if not hasattr(flask.current_app, "arborist"):
#         raise Forbidden(
#             "this fence instance is not configured with arborist;"
#             " this endpoint is unavailable"
#         )

#     created_user = flask.current_app.arborist.create_user(dict(name=user.username))

#     if policies is None:
#         policies = ["login_no_access", "analysis"]

#     for policy_name in policies:
#         policy = flask.current_app.arborist.get_policy(policy_name)
#         if not policy:
#             raise NotFound(
#                 "Policy {} NOT FOUND".format(
#                     policy_name
#                 )
#             )

#         res = flask.current_app.arborist.grant_user_policy(user.username, policy_name)
#         if res is None:
#             raise ArboristError(
#                 "Policy {} has not been assigned.".format(
#                     policy["id"]
#                 )
#             )