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


def is_company_legit(company, typed_company):
    return company == typed_company


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
    r = request_hubspot(data=data, path="/contacts/search")
    # {"total": 0, "results": []}
    r = r.json()
    if len(r.get("results")) < 1:
    	return None

    user_properties = r.get("results")[0].get("properties")
    return {
        "firstName": user_properties.get("firstname"),
        "lastName": user_properties.get("lastname"),
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
    r = request_hubspot(data=data, path="/contacts")

    success = r.status_code == requests.codes.created
    if not success:
        raise Exception(
            "User registration on HubSpot failed: " + r.json()
        )
    r = r.json()
    return (r.get("id"), r.get("properties"))


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
    r_get = request_hubspot(data=data_get, path="/contacts/search")
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
    if not success:
        raise Exception(
            "User update on HubSpot failed: " + r_update.json()
        )
    r_update = r_update.json()
    return (r_update.get("id"), r_update.get("properties"))


def get_associated_company(hubspot_id):
    # data_user_id = {
    #     "filterGroups": [{
    #         "filters": [{
    #             "value": email,
    #             "propertyName": "email",
    #             "operator": "EQ"
    #         }]
    #     }],
    #     "properties": [""]
    # }
    # r_user_id = request_hubspot(data=data_user_id, path="/contacts/search")
    # user_id = r_user_id.json().get("results")[0].get("id")

    r_company_id = request_hubspot(
        method="GET", path=f"/contacts/{hubspot_id}/associations/companies")
    company_id_results = r_company_id.json().get("results")

    if len(company_id_results) == 0:
        return None
    else:
        company_id = company_id_results[0].get("id")
        r_company = request_hubspot(
            method="GET", path=f"/companies/{company_id}")
        company_properties = r_company.json().get("properties")
        return company_properties


def update_user_info(email, user_info):
    hubspot_id = None
    properties = None
    if is_user(email, None):
        hubspot_id, properties = update_user(email, user_info)
    else:
        hubspot_id, properties = create_user(email, user_info)

    company = get_associated_company(hubspot_id)
    if company is None:
        send_email_ses("User with email: " + email + " needs an 'Associated Company' to be able to use all the functionality of the portal. Please refer to the user input in the 'Institution' field to associate the user to the correct company.", None, "PCDC GEN3 User Registration - Missing company")
    elif not is_company_legit(company.get("name"), properties["institution"]):
        send_email_ses("User with email: " + email + " has an 'Associated Company' that doesn't match the company typed during registration. Please refer to the user input in the 'Institution' field to doublecheck on it. In case of a simple typos please update the 'Institution' field, while in case the 'Institution' field is a different company please update the 'Associated Company' field. The 'Institution' field has to match with the 'Associated Company' name.", None, "PCDC GEN3 User Registration - Mismatching company")

    return hubspot_id


