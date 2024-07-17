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


logger = get_logger(__name__)

PROMETHEUS_TMP_COUNTER_DIR = tempfile.TemporaryDirectory()

os.environ["prometheus_multiproc_dir"] = PROMETHEUS_TMP_COUNTER_DIR.name


class Metrics:
    """
    Class to handle Prometheus metrics
    Attributes:
        registry (CollectorRegistry): Prometheus registry
        metrics (dict): Dictionary to store Prometheus metrics
    """

    def __init__(self):
        self.registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(self.registry)
        self.metrics = {}

    def get_or_create_counter(self, name, labels):
        """
        Create a Prometheus counter metric
        Args:
            name (str): Name of the metric
            description (str): Description of the metric
            labels (list): List of labels for the metric
        """
        description = {
            "gen3_fence_presigned_url_total": "Fence presigned urls",
            "gen3_fence_logins_total": "Fence logins",
        }.get(name, name)
        logger.info(
            f"Creating counter '{name}' with description '{description}' and labels: {labels}"
        )
        if name not in self.metrics:
            counter = Counter(name, description, [*labels.keys()])
            self.metrics[name] = counter
        elif type(self.metrics[name]) != Counter:
            raise ValueError(
                f"Trying to create counter '{name}' but a gauge with this name already exists"
            )
        return self.metrics[name]

    def get_or_create_gauge(self, name, labels):
        """
        Create a Prometheus gauge metric
        Args:
            name (str): Name of the metric
            description (str): Description of the metric
            labels (list): List of labels for the metric
        """
        description = {
            "gen3_fence_presigned_url_size": "Fence presigned urls",
        }.get(name, name)
        logger.info(
            f"Creating gauge '{name}' with description '{description}' and labels: {labels}"
        )
        if name not in self.metrics:
            gauge = Gauge(name, description, [*labels.keys()])
            self.metrics[name] = gauge
        elif type(self.metrics[name]) != Gauge:
            raise ValueError(
                f"Trying to create counter '{name}' but a gauge with this name already exists"
            )
        return self.metrics[name]

    def increment_counter(self, name, labels):
        """
        Increment a Prometheus counter metric
        Args:
            name (str): Name of the metric
            labels (dict): Dictionary of labels for the metric
        """
        counter = self.get_or_create_counter(name, labels)
        logger.debug(f"Incrementing counter '{name}' with labels: {labels}")
        counter.labels(*labels.values()).inc()

    def set_gauge(self, name, labels, value):
        """
        Set a Prometheus gauge metric
        Args:
            name (str): Name of the metric
            labels (dict): Dictionary of labels for the metric
            value (int): Value to set the metric to
        """
        self.get_or_create_gauge(name, labels)
        logger.debug(f"Setting gauge '{name}' with labels: {labels}")
        self.metrics[name].labels(*labels.values()).set(value)

    def generate_latest_metrics(self):
        """
        Generate the latest Prometheus metrics
        Returns:
            str: Latest Prometheus metrics
            str: Content type of the latest Prometheus metrics
        """
        return generate_latest(self.registry), CONTENT_TYPE_LATEST

    def init_app(self, app):
        """
        Initialize the Prometheus metrics app
        Args:
            app (Flask): Flask app
        """
        app.registry = self.registry


# Initialize the Metrics instance
metrics = Metrics()
