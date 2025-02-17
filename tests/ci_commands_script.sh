#!/usr/bin/env bash

mkdir -p /var/tmp/uwsgi_flask_metrics/ || true
export PROMETHEUS_MULTIPROC_DIR="/var/tmp/uwsgi_flask_metrics/"
echo "running tests"
poetry run pytest -vv --cov=fence --cov-report xml .
#poetry run pytest -vv --cov=fence --cov-report xml tests
