"""
This module is supposed to hold operations for projects. Its main
responsibility is transforming the Project object borne information into a
dictionary that shield the rest of the modules from the particular
implementation of this object.

In the event of modifying the logic from the functions in userdatamodel, please
replace the direct imports with a whole function (of the same name) that holds
this logic.
"""

from fence.resources.userdatamodel import (
    get_project,
    get_all_projects,
    get_project_info,
    create_project,
    delete_project,
    create_bucket_on_project,
    delete_bucket_on_project,
    list_buckets_on_project,
)
