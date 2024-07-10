import tempfile
import os
from cdislogging import get_logger
from prometheus_client import (
    CollectorRegistry,
    multiprocess,
    Counter,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

logger = get_logger(__name__)

PROMETHEUS_TMP_COUNTER_DIR = tempfile.TemporaryDirectory()


class Metrics:
    def __init__(self):
        self.registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(self.registry)
        self.metrics = {}

    def create_counter(self, name, description, labels):
        if name not in self.metrics:
            counter = Counter(name, description, [labels])
            self.metrics[name] = counter
        else:
            raise ValueError(f"Metric {name} already exists")

    def create_gauge(self, name, description, labels):
        if name not in self.metrics:
            gauge = Gauge(name, description, [labels])
            self.metrics[name] = gauge
        else:
            raise ValueError(f"Metric {name} already exists")

    def increment_counter(self, name, description, labels):
        if name in self.metrics:
            logger.info(
                f"Incrementing counter {name} with label {labels} and description {description}"
            )
            self.metrics[name].labels(*labels.values()).inc()
        else:
            logger.info(
                f"Creating counter {name} with label {labels} and description {description}"
            )
            self.create_counter(name, description, labels.keys())
            self.metrics[name].labels(*labels.values()).inc()

    def set_gauge(self, name, description, labels, value):
        if name in self.metrics:
            logger.info(
                f"Setting gauge {name} with label {labels} and description {description}"
            )
            self.metrics[name].labels(*labels.values()).set(value)
        else:
            logger.info(
                f"Creating gauge {name} with label {labels} and description {description}"
            )
            self.create_gauge(name, description, labels.keys())
            self.metrics[name].labels(*labels.values()).set(value)

    def generate_latest_metrics(self):
        return generate_latest(self.registry), CONTENT_TYPE_LATEST

    def init_app(self, app):
        app.registry = self.registry


# Initialize the Metrics instance
metrics = Metrics()
