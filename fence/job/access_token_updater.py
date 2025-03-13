import asyncio
import datetime
import time

from cdislogging import get_logger
from flask import current_app

from fence.config import config
from fence.models import User
from fence.resources.openid.ras_oauth2 import RASOauth2Client as RASClient
from fence.resources.openid.idp_oauth2 import Oauth2ClientBase as OIDCClient


logger = get_logger(__name__, log_level="debug")


class TokenAndAuthUpdater(object):
    def __init__(
        self,
        chunk_size=None,
        concurrency=None,
        thread_pool_size=None,
        buffer_size=None,
        logger=logger,
        arborist=None,
    ):
        """
        args:
            chunk_size: size of chunk of users we want to take from each iteration
            concurrency: number of concurrent users going through the visa update flow
            thread_pool_size: number of Docker container CPU used for jwt verifcation
            buffer_size: max size of queue
        """
        self.chunk_size = chunk_size or 10
        self.concurrency = concurrency or 5
        self.thread_pool_size = thread_pool_size or 3
        self.buffer_size = buffer_size or 10
        self.n_workers = self.thread_pool_size + self.concurrency
        self.logger = logger

        # This job runs without an application context, so it cannot use the
        # current_app.jwt_public_keys cache.
        # This is a simple dict with the same lifetime as the job.
        # When there are many visas from many issuers it will make sense to
        # implement a more persistent cache.
        self.pkey_cache = {}

        self.visa_types = config.get("USERSYNC", {}).get("visa_types", {})

        # Dict on self which contains all clients that need update
        self.oidc_clients_requiring_token_refresh = {}

        # keep this as a special case, because RAS will not set group information configuration.
        oidc = config.get("OPENID_CONNECT", {})

        if "ras" not in oidc:
            self.logger.error("RAS client not configured")
        else:
            ras_client = RASClient(
                oidc["ras"],
                HTTP_PROXY=config.get("HTTP_PROXY"),
                logger=logger,
            )
            self.oidc_clients_requiring_token_refresh["ras"] = ras_client

        self.arborist = arborist

        # Initialise a client for each OIDC client in oidc, which does have is_authz_groups_sync_enabled set to true and add them
        # to oidc_clients_requiring_token_refresh
        for oidc_name, settings in oidc.items():
            if settings.get("is_authz_groups_sync_enabled", False):
                oidc_client = OIDCClient(
                    settings=settings,
                    HTTP_PROXY=config.get("HTTP_PROXY"),
                    logger=logger,
                    idp=oidc_name,
                    arborist=arborist,
                )
                self.oidc_clients_requiring_token_refresh[oidc_name] = oidc_client

    async def update_tokens(self, db_session):
        """
        Initialize a producer-consumer workflow.

        Producer: Collects users from db and feeds it to the workers
          Worker: Takes in the users from the Producer and passes it to the Updater to
                  update the tokens and passes those updated tokens for JWT validation
         Updater: Updates refresh_tokens and visas by calling the update_user_authorization
                  from the correct client

        """
        start_time = time.time()
        self.logger.info("Initializing Visa Update and Token refreshing Cronjob . . .")
        self.logger.info("Total concurrency size: {}".format(self.concurrency))
        self.logger.info("Total thread pool size: {}".format(self.thread_pool_size))
        self.logger.info("Total buffer size: {}".format(self.buffer_size))
        self.logger.info("Total number of workers: {}".format(self.n_workers))

        queue = asyncio.Queue(maxsize=self.buffer_size)
        updater_queue = asyncio.Queue(maxsize=self.n_workers)
        loop = asyncio.get_event_loop()

        producers = loop.create_task(self.producer(db_session, queue, chunk_idx=0))
        workers = [
            loop.create_task(self.worker(j, queue, updater_queue))
            for j in range(self.n_workers)
        ]
        updaters = [
            loop.create_task(self.updater(i, updater_queue, db_session))
            for i in range(self.concurrency)
        ]

        await asyncio.gather(producers)
        self.logger.info("Producers done producing")
        await queue.join()

        await asyncio.gather(*workers)
        await updater_queue.join()  # blocks until everything in updater_queue is complete

        for u in updaters:
            u.cancel()

        self.logger.info(
            "Visa cron job completed in {}".format(
                datetime.timedelta(seconds=time.time() - start_time)
            )
        )

    async def get_user_from_db(self, db_session, chunk_idx):
        """
        Window function to get chunks of data from the table
        """
        start, stop = self.chunk_size * chunk_idx, self.chunk_size * (chunk_idx + 1)
        users = db_session.query(User).slice(start, stop).all()
        return users

    async def producer(self, db_session, queue, chunk_idx):
        """
        Produces users from db and puts them in a queue for processing
        """
        chunk_size = self.chunk_size
        while True:
            users = await self.get_user_from_db(db_session, chunk_idx)

            if users == None:
                break
            for user in users:
                self.logger.info("Producer producing user {}".format(user.username))
                await queue.put(user)
            if len(users) < chunk_size:
                break
            chunk_idx += 1

    async def worker(self, name, queue, updater_queue):
        """
        Create tasks to pass to updater to update visas.
        """
        while not queue.empty():
            user = await queue.get()
            await updater_queue.put(user)
            queue.task_done()

    async def updater(self, name, updater_queue, db_session):
        while True:
            try:
                user = await updater_queue.get()
                if user is None:  # Use None to signal termination
                    break

                client = self._pick_client(user)
                if client:
                    self.logger.info(
                        "Updater {} updating authorization for user {}".format(
                            name, user.username
                        )
                    )
                    # when getting access token, this persists new refresh token,
                    # it also persists validated visa(s) in the database
                    client.update_user_authorization(
                        user,
                        pkey_cache=self.pkey_cache,
                        db_session=db_session,
                    )

                else:
                    self.logger.debug(
                        f"Updater {name} NOT updating authorization for "
                        f"user {user.username} because no client was found for IdP: {user.identity_provider}"
                    )

                updater_queue.task_done()

            except Exception as exc:
                self.logger.error(
                    f"Updater {name} could not update authorization "
                    f"for {user.username if user else 'unknown user'}. Error: {exc}. Continuing."
                )
                # Ensure task is marked done if exception occurs
                updater_queue.task_done()

    def _pick_client(self, user):
        """
        Select OIDC client based on identity provider.
        """

        client = self.oidc_clients_requiring_token_refresh.get(
            getattr(user.identity_provider, "name"), None
        )
        if client:
            self.logger.info(f"Picked client: {client.idp} for user {user.username}")
        else:
            self.logger.info(f"No client found for user {user.username}")
        return client

    def _pick_client_from_visa(self, visa):
        """
        Pick oidc client according to the visa provider
        """
        client = None
        if visa.type in self.visa_types["ras"]:
            client = self.ras_client
        else:
            raise Exception(
                "Visa type {} not configured in fence-config".format(visa.type)
            )
        if not client:
            raise Exception(
                "Visa Client not set up or not available for type {}".format(visa.type)
            )
        return client
