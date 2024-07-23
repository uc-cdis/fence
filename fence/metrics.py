import os
import tempfile

from prometheus_client import (
    CollectorRegistry,
    multiprocess,
    Counter,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
)
from cdislogging import get_logger

from fence.config import config


logger = get_logger(__name__)


class Metrics:
    """
    Class to handle Prometheus metrics
    Attributes:
        registry (CollectorRegistry): Prometheus registry
        metrics (dict): Dictionary to store Prometheus metrics
    """

    def __init__(self, path):
        os.environ["prometheus_multiproc_dir"] = path
        self._registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(self._registry)
        self._metrics = {}

        # set the descriptions of new metrics here. Descriptions not specified here
        # will default to the metric name.
        self._counter_descriptions = {
            "gen3_fence_presigned_url": "Fence presigned urls",
            "gen3_fence_login": "Fence logins",
        }
        self._gauge_descriptions = {
            "gen3_fence_presigned_url_size": "Fence presigned urls",
        }

    def get_latest_metrics(self):
        """
        Generate the latest Prometheus metrics
        Returns:
            str: Latest Prometheus metrics
            str: Content type of the latest Prometheus metrics
        """
        return generate_latest(self._registry), CONTENT_TYPE_LATEST

    def _increment_counter(self, name, labels):
        """
        Increment a Prometheus counter metric.
        Note that this function should not be called directly - implement a function like
        `add_login_event` instead. A metric's labels should always be consistent.
        Args:
            name (str): Name of the metric
            labels (dict): Dictionary of labels for the metric
        """
        # create the counter if it doesn't already exist
        if name not in self._metrics:
            description = self._counter_descriptions.get(name, name)
            logger.info(
                f"Creating counter '{name}' with description '{description}' and labels: {labels}"
            )
            self._metrics[name] = Counter(name, description, [*labels.keys()])
        elif type(self._metrics[name]) != Counter:
            raise ValueError(
                f"Trying to create counter '{name}' but a gauge with this name already exists"
            )

        logger.debug(f"Incrementing counter '{name}' with labels: {labels}")
        self._metrics[name].labels(*labels.values()).inc()

    def _set_gauge(self, name, labels, value):
        """
        Set a Prometheus gauge metric.
        Note that this function should not be called directly - implement a function like
        `add_signed_url_event` instead. A metric's labels should always be consistent.
        Args:
            name (str): Name of the metric
            labels (dict): Dictionary of labels for the metric
            value (int): Value to set the metric to
        """
        # create the gauge if it doesn't already exist
        if name not in self._metrics:
            description = self._gauge_descriptions.get(name, name)
            logger.info(
                f"Creating gauge '{name}' with description '{description}' and labels: {labels}"
            )
            self._metrics[name] = Gauge(name, description, [*labels.keys()])
        elif type(self._metrics[name]) != Gauge:
            raise ValueError(
                f"Trying to create gauge '{name}' but a counter with this name already exists"
            )

        logger.debug(f"Setting gauge '{name}' with labels: {labels}")
        self._metrics[name].labels(*labels.values()).set(value)

    def add_login_event(self, user_sub, idp, fence_idp, shib_idp, client_id):
        """
        Record a login event
        """
        if not config["ENABLE_PROMETHEUS_METRICS"]:
            return
        self._increment_counter(
            "gen3_fence_login",
            {
                "user_sub": user_sub,
                "idp": idp,
                "client_id": client_id,
                "fence_idp": fence_idp,
                "shib_idp": shib_idp,
            },
        )
        self._increment_counter(
            "gen3_fence_login",
            {
                "user_sub": user_sub,
                "idp": "all",
                "client_id": client_id,
                # when counting all IDPs, we don't care about the fence and ship IDP values
                "fence_idp": None,
                "shib_idp": None,
            },
        )

    def add_signed_url_event(
        self,
        action,
        protocol,
        acl,
        authz,
        bucket,
        user_sub,
        client_id,
        drs,
        size_in_kibibytes,
    ):
        """
        Record a signed URL event
        """
        if not config["ENABLE_PROMETHEUS_METRICS"]:
            return
        self._increment_counter(
            "gen3_fence_presigned_url",
            {
                "action": action,
                "protocol": protocol,
                "acl": acl,
                "authz": authz,
                "bucket": bucket,
                "user_sub": user_sub,
                "client_id": client_id,
                "drs": drs,
            },
        )
        self._set_gauge(
            "gen3_fence_presigned_url_size",
            {
                "action": action,
                "protocol": protocol,
                "acl": acl,
                "authz": authz,
                "bucket": bucket,
                "user_sub": user_sub,
                "client_id": client_id,
                "drs": drs,
            },
            size_in_kibibytes,
        )


# Initialize the Metrics instance
PROMETHEUS_TMP_COUNTER_DIR = tempfile.TemporaryDirectory()
metrics = Metrics(path=PROMETHEUS_TMP_COUNTER_DIR.name)
