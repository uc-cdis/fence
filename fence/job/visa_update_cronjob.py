from fence.models import GA4GHVisaV1
from fence.resources.openid.ras_oauth2 import RASOauth2Client as RASClient

# Base class that collects only specific type of refresh token 


class Visa_Update(object):
    def __init__(
        self,
        visa_type=None
    ):
        self.visa_type = visa_type