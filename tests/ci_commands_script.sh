#!/usr/bin/env bash

rm -Rf /var/tmp/uwsgi_flask_metrics/
mkdir -p /var/tmp/uwsgi_flask_metrics/
export PROMETHEUS_MULTIPROC_DIR="/var/tmp/uwsgi_flask_metrics/"
poetry run pytest -vv --cov=fence --cov-report xml tests
