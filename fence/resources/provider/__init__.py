"""
This module is supposed to hold the transformation between the provider object
that defines it in the database into a dictionary that can be used in the rest
of the code without the need for imports all over the code.  Right now, since
the transformation is lacking and the code was not being used, this module acts
as an interface to keep congruence with the rest of the modules at this level.
Please use and expand accordingly.
"""

from fence.resources.userdatamodel import get_provider, create_provider, delete_provider
