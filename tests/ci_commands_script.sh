#!/usr/bin/env bash

mkdir -p /var/tmp/prometheus_metrics/ || true
export PROMETHEUS_MULTIPROC_DIR="/var/tmp/prometheus_metrics/"
poetry run pytest -vv --cov=fence --cov=migrations/versions --cov-report xml tests
