import flask
import requests

import re

from json import dumps
from fence.config import config
from fence.utils import send_email_ses



def request_hubspot(data={}, method="POST", path="/"):
    url = "https://api.hubapi.com/crm/v3/objects" + path
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }
    querystring = {"hapikey": flask.current_app.hubspot_api_key}
    return requests.request(method, url, data=dumps(data), headers=headers, params=querystring)


#TODO is this used at all???
def is_domain(name):
    # copied from https://validators.readthedocs.io/en/latest/_modules/validators/domain.html
    pattern = re.compile(
        r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
    )
    return pattern.match(name)


def get_user(email, hubspot_id):
    data = {
        "filterGroups": [{
            "filters": [{
                "value": email,
                "propertyName": "email",
                "operator": "EQ"
            }]
        }],
        "properties": ["firstname", "lastname", "institution"]
    }
    print("GET HUB USER")
    r = request_hubspot(data=data, path="/contacts/search")
    # {"total": 0, "results": []}
    r = r.json()
    if len(r.get("results")) < 1:
    	return None

    user_properties = r.get("results")[0].get("properties")
    return {
        "firstname": user_properties.get("firstname"),
        "lastname": user_properties.get("lastname"),
        "institution": user_properties.get("institution")
    }
    # return flask.jsonify({"user": {
    #     "firstname": user_properties.get("firstname"),
    #     "lastname": user_properties.get("lastname"),
    #     "institution": user_properties.get("institution"),
    # }})

def is_user(email, hubspot_id):
    data = {
        "filterGroups": [{
            "filters": [{
                "value": email,
                "propertyName": "email",
                "operator": "EQ"
            }]
        }],
        "properties": [""]
    }
    r = request_hubspot(data=data, path="/contacts/search")
    registered = r.json().get("total", 0) > 0
    # return flask.jsonify({"registered": registered})
    return registered

# {
#     "total": 1,
#     "results": [
#         {
#             "id": "14851",
#             "properties": {
#                 "createdate": "2020-04-09T18:29:50.923Z",
#                 "firstname": "Luca",
#                 "hs_object_id": "14851",
#                 "institution": null,
#                 "lastmodifieddate": "2021-01-08T15:39:33.365Z",
#                 "lastname": "Graglia"
#             },
#             "createdAt": "2020-04-09T18:29:50.923Z",
#             "updatedAt": "2021-01-08T15:39:33.365Z",
#             "archived": false
#         }
#     ]
# }




def create_user(email, user_info):
    data = {
        "properties": {
            "email": email,
            "firstname": user_info["firstName"],
            "institution": user_info["institution"],
            "lastname": user_info["lastName"],
        }
    }
    print("CREATE HUB USER")
    r = request_hubspot(data=data, path="/contacts")
    print(r)
    print(r.json())
    print(dumps(r))
    success = r.status_code == requests.codes.created
    #TODO thrpw error if not success
    return flask.jsonify({"success": success})


def update_user(email, user_info):
    data_get = {
        "filterGroups": [{
            "filters": [{
                "value": email,
                "propertyName": "email",
                "operator": "EQ"
            }]
        }],
        "properties": [""]
    }
    print("UPDATES HUB USER")
    r_get = request_hubspot(data=data_get, path="/contacts/search")
    print(dumps(r_get))
    user_id = r_get.json().get("results")[0].get("id")

    data_update = {
        "properties": {
            "firstname": user_info["firstName"],
            "institution": user_info["institution"],
            "lastname": user_info["lastName"],
        }
    }
    r_update = request_hubspot(
        data=data_update, method="PATCH", path=f"/contacts/{user_id}")
    success = r_update.status_code == requests.codes.ok
    #TODO thrpw error if not success
    return user_id

# {
#     "id": "14851",
#     "properties": {
#         "firstname": "Luca",
#         "institution": "University of Chicago",
#         "lastmodifieddate": "2021-01-18T02:42:39.069Z",
#         "lastname": "Graglia"
#     },
#     "createdAt": "2020-04-09T18:29:50.923Z",
#     "updatedAt": "2021-01-18T02:42:39.069Z",
#     "archived": false
# }


def get_associated_company(email):
    data_user_id = {
        "filterGroups": [{
            "filters": [{
                "value": email,
                "propertyName": "email",
                "operator": "EQ"
            }]
        }],
        "properties": [""]
    }
    r_user_id = request_hubspot(data=data_user_id, path="/contacts/search")
    user_id = r_user_id.json().get("results")[0].get("id")

    r_company_id = request_hubspot(
        method="GET", path=f"/contacts/{user_id}/associations/companies")
    company_id_results = r_company_id.json().get("results")
    if len(company_id_results) == 0:
        return None
    else:
        company_id = company_id_results[0].get("id")
        r_company = request_hubspot(
            method="GET", path=f"/companies/{company_id}")
        company_properties = r_company.json().get("properties")
        return {"name": company_properties.get("name")}

# {
#     "id": "2498298527",
#     "properties": {
#         "createdate": "2019-10-15T15:20:24.594Z",
#         "domain": "uchicago.edu",
#         "hs_lastmodifieddate": "2021-01-12T21:49:48.218Z",
#         "hs_object_id": "2498298527",
#         "name": "The University of Chicago"
#     },
#     "createdAt": "2019-10-15T15:20:24.594Z",
#     "updatedAt": "2021-01-12T21:49:48.218Z",
#     "archived": false
# }


def update_user_info(email, user_info):
    hubspot_id = None
    if is_user(email, None):
        hubspot_id = update_user(email, user_info)
    else:
        create_user(email, user_info)
        #TODO call hubspot API and return id
        hubspot_id = 1

    company = get_associated_company(email)
    if company is None:
        #TODO finish an test
        send_email_ses("User " + email + " has needs an Associated company", None, "PCDC GEN3 User Registration - Missing company")

    return hubspot_id











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







