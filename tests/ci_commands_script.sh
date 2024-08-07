#!/usr/bin/env bash

# Get the directory of the current script
SCRIPT_DIR="$(dirname "$(realpath "$0")")"

# assumes Fence repo folder structure
RELATIVE_PATH="../deployment/scripts/metrics/setup_prometheus"
METRICS_SETUP_SCRIPT_PATH="$(realpath "$SCRIPT_DIR/$RELATIVE_PATH")"

echo "The full path to the METRICS_SETUP_SCRIPT_PATH file is: $METRICS_SETUP_SCRIPT_PATH"

# Check if the script exists and is executable
if [ -x "$METRICS_SETUP_SCRIPT_PATH" ]; then
    echo "Running $METRICS_SETUP_SCRIPT_PATH"
    source "$METRICS_SETUP_SCRIPT_PATH" /var/tmp/prometheus_metrics
else
    echo "$METRICS_SETUP_SCRIPT_PATH does not exist or is not executable. Attempting test run anyway..."
fi

poetry run pytest -vv --cov=fence --cov-report xml
