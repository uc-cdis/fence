from fence import config, logger, app, tempfile, os, DispatcherMiddleware

# for some reason the temp dir does not get created properly if we move
# this statement to `_setup_prometheus()`
PROMETHEUS_TMP_COUNTER_DIR = tempfile.TemporaryDirectory()


def _setup_prometheus(app):
    # This environment variable MUST be declared before importing the
    # prometheus modules (or unit tests fail)
    # More details on this awkwardness: https://github.com/prometheus/client_python/issues/250
    os.environ["prometheus_multiproc_dir"] = PROMETHEUS_TMP_COUNTER_DIR.name

    from prometheus_client import (
        CollectorRegistry,
        multiprocess,
        make_wsgi_app,
        Counter,
    )

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
        "fence_login_requests_total",
        "Total number of login requests",
        registry=app.prometheus_registry,
    )


app.prometheus_counters = {}
if config["ENABLE_PROMETHEUS_METRICS"]:
    logger.info("Enabling Prometheus metrics...")
    _setup_prometheus(app)
else:
    logger.info("Prometheus metrics are NOT enabled.")
