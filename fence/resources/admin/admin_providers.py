from fence.resources import (
    userdatamodel as udm,
    project as pj,
    group as gp,
    user as us,
    provider as pv
)

from flask import current_app as capp
from fence.data_model.models import User, Group
from fence.errors import NotFound
import json
from fence.errors import UserError


#### CLOUD PROVIDER ####


def get_provider(current_session, provider_name):
    """
    Return all the information associated with
    a provider.
    Returns a dictionary.
    """
    return pv.get_provider(current_session, provider_name)

def create_provider(
        current_session,
        provider_name,
        backend=None,
        service=None,
        endpoint=None,
        description=None):
    """
    Create a provider in the userdatamodel
    database.
    Returns a dictionary.
    """
    return pv.create_provider(
        current_session,
        provider_name,
        backend,
        service,
        endpoint,
        description
    )

def delete_provider_by_name(current_session, provider_name):
    """
    Remove a cloud provider from the database.
    All projects associated with it should be removed
    prior to calling this function.
    Returns a dictionary.
    """
    return udm.delete_provider(current_session, provider_name)
