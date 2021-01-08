import asyncio

from fence.config import config
from fence.models import GA4GHVisaV1
from fence.resources.openid.ras_oauth2 import RASOauth2Client as RASClient

# Base class that collects only specific type of refresh token 


class Visa_Token_Update(object):
    def __init__(
        self,
        visa_type=None,
        concurrency=None, # number of concurrent users going through the visa update flow
        thread_pool_size=None, # number of Docker container CPU used for jwt verification
        buffer_size=None, # max size of asyncio queue
    ):
        self.visa_type = visa_type or "ras"
        self.concurrency = concurrency or 3
        self.thread_pool_size = thread_pool_size or 2
        self.buffer_size = buffer_size or 10
        
