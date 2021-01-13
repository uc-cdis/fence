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
        self.n_workers = self.thread_pool_size + self.concurrency
        
    async def update_tokens(self):
        """
        Have dictionary or something to decide which client to use. Can go through the whole list and decide which client to use 
        looking at the type field in the ga4gh table. 
        """
        
        queue = asyncio.Queue(maxsize=self.buffer_size)

        # Iterate through all users in upstream_refresh_token table (or should it be the ga4gh_visa_v1 table since we want to maximize access)
            # No case where there might be a refresh token but no visa so should iterate through the visa table

            # 


        # Check what type of visa they have 

        # Depending on the type of visa change their OauthClient 

        

    async def producer(self, queue):
        """
        TODO: Rename this
        Producer: Produces users and puts them in a queue for processing

        """

    async def consumer(self, queue):
        """
        TODO: Rename this
        Consumer: Create workers that does the visa update flow 
