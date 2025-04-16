#!/usr/bin/env bash

mkdir -p /var/tmp/uwsgi_flask_metrics/ || true
export PROMETHEUS_MULTIPROC_DIR="/var/tmp/uwsgi_flask_metrics/"
poetry run pytest -vv --cov=fence --cov=migrations/versions --cov-report xml tests
