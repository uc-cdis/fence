import tempfile
import os
from prometheus_client import (
    CollectorRegistry,
    multiprocess,
    make_wsgi_app,
    Counter,
    Gauge,
)
from werkzeug.middleware.dispatcher import DispatcherMiddleware

PROMETHEUS_TMP_COUNTER_DIR = tempfile.TemporaryDirectory()


class Metrics:
    def __init__(self):
        self.presigned_url_counter = None
        self.login_counter = None
        self.fence_login_counter = None
        self.google_login_counter = None
        self.ras_login_counter = None
        self.presigned_urls_ga4gh_drs_counter = None
        self.presigned_url_download_protocol_gcs_counter = None
        self.presigned_url_download_protocol_s3_counter = None
        self.presigned_url_data_metrics_size_gauge = None

    def initialize_metrics(self, app):
        os.environ["prometheus_multiproc_dir"] = PROMETHEUS_TMP_COUNTER_DIR.name
        app.prometheus_registry = CollectorRegistry()
        multiprocess.MultiProcessCollector(app.prometheus_registry)

        # Add prometheus wsgi middleware to route /metrics requests
        app.wsgi_app = DispatcherMiddleware(
            app.wsgi_app, {"/metrics": make_wsgi_app(registry=app.prometheus_registry)}
        )
        self.presigned_url_counter = Counter(
            "fence_presigned_url_requests_total",
            "Total number of presigned URL requests",
            registry=app.prometheus_registry,
        )
        self.login_counter = Counter(
            "fence_all_login_requests_total",
            "Total number of login requests",
            registry=app.prometheus_registry,
        )
        self.fence_login_counter = Counter(
            "fence_login_requests_total",
            "Total number of fence login requests",
            registry=app.prometheus_registry,
        )
        self.google_login_counter = Counter(
            "google_login_requests_total",
            "Total number of Google login requests",
            registry=app.prometheus_registry,
        )
        self.ras_login_counter = Counter(
            "fence_ras_login_requests_total",
            "Total number of RAS login requests",
            registry=app.prometheus_registry,
        )
        self.presigned_urls_ga4gh_drs_counter = Counter(
            "fence_presigned_urls_ga4gh_drs_requests_total",
            "Total number of presigned URL requests for GA4GH DRS",
            registry=app.prometheus_registry,
        )
        self.presigned_url_download_protocol_gcs_counter = Counter(
            "fence_presigned_url_download_protocol_gcs_requests_total",
            "Total number of presigned URL requests for GCS",
            registry=app.prometheus_registry,
        )
        self.presigned_url_download_protocol_s3_counter = Counter(
            "fence_presigned_url_download_protocol_s3_requests_total",
            "Total number of presigned URL requests for S3",
            registry=app.prometheus_registry,
        )
        self.presigned_url_data_metrics_size_gauge = Gauge(
            "fence_presigned_url_data_metrics_size_bytes",
            "Size of data metrics in bytes",
            registry=app.prometheus_registry,
        )


metrics = Metrics()
