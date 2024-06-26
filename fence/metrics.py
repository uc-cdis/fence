import tempfile
import os
from fence.config import config
from fence import app


# for some reason the temp dir does not get created properly if we move
# this statement to `_setup_prometheus()`
PROMETHEUS_TMP_COUNTER_DIR = tempfile.TemporaryDirectory()


if config["ENABLE_PROMETHEUS_METRICS"]:
    from fence import logger

    app.prometheus_counters = {}
    from werkzeug.middleware.dispatcher import DispatcherMiddleware
    from prometheus_client import (
        CollectorRegistry,
        multiprocess,
        make_wsgi_app,
        Counter,
        Gauge,
    )

    # This environment variable MUST be declared before importing the
    # prometheus modules (or unit tests fail)
    # More details on this awkwardness: https://github.com/prometheus/client_python/issues/250
    os.environ["prometheus_multiproc_dir"] = PROMETHEUS_TMP_COUNTER_DIR.name

    app.prometheus_registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(app.prometheus_registry)

    # Add prometheus wsgi middleware to route /metrics requests
    app.wsgi_app = DispatcherMiddleware(
        app.wsgi_app, {"/metrics": make_wsgi_app(registry=app.prometheus_registry)}
    )

    presigned_url_counter = Counter(
        "fence_presigned_url_requests_total",
        "Total number of presigned URL requests",
        registry=app.prometheus_registry,
    )

    login_counter = Counter(
        "fence_all_login_requests_total",
        "Total number of login requests",
        registry=app.prometheus_registry,
    )

    fence_login_counter = Counter(
        "fence_login_requests_total",
        "Total number of fence login requests",
        registry=app.prometheus_registry,
    )

    google_login_counter = Counter(
        "google_login_requests_total",
        "Total number of Google login requests",
        registry=app.prometheus_registry,
    )

    ras_login_counter = Counter(
        "fence_ras_login_requests_total",
        "Total number of RAS login requests",
        registry=app.prometheus_registry,
    )

    presigned_urls_ga4gh_drs_counter = Counter(
        "fence_presigned_urls_ga4gh_drs_requests_total",
        "Total number of presigned URL requests for GA4GH DRS",
        registry=app.prometheus_registry,
    )

    presigned_url_download_protocol_gcs_counter = Counter(
        "fence_presigned_url_download_protocol_gcs_requests_total",
        "Total number of presigned URL requests for GCS",
        registry=app.prometheus_registry,
    )

    presigned_url_download_protocol_s3_counter = Counter(
        "fence_presigned_url_download_protocol_s3_requests_total",
        "Total number of presigned URL requests for S3",
        registry=app.prometheus_registry,
    )

    presigned_url_data_metrics_size_gauge = Gauge(
        "fence_presigned_url_data_metrics_size_bytes",
        "Size of data metrics in bytes",
        registry=app.prometheus_registry,
    )

else:
    logger.info("Prometheus metrics are NOT enabled.")
