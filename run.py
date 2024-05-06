import argparse

from alembic.config import main as alembic_main

from fence import app, app_init, config

# Prometheus metrics exporter
from prometheus_flask_exporter.multiprocess import UWsgiPrometheusMetrics

metrics = UWsgiPrometheusMetrics(app, path=None)

# Serve metrics on port 9090
metrics.start_http_server(9090)

parser = argparse.ArgumentParser()
parser.add_argument(
    "-c",
    "--config_file_name",
    help="Name for file is something other than "
    "fence-config.yaml. Will search in defined search folders specified in "
    "fence's settings. To automatically create configs, check out the "
    'cfg_help.py file in this directory. Run "python cfg_help.py --help".',
    default="fence-config.yaml",
)
parser.add_argument(
    "--config_path",
    help="Full path to a yaml config file for fence. Will not"
    " search directories for config.",
)
args = parser.parse_args()

if config.get("MOCK_STORAGE"):
    from mock import patch
    from tests.storageclient.storage_client_mock import get_client

    patcher = patch("fence.resources.storage.get_client", get_client)
    patcher.start()

if config.get("ENABLE_DB_MIGRATION"):
    alembic_main(["--raiseerr", "upgrade", "head"])

app_init(app, config_path=args.config_path, config_file_name=args.config_file_name)

app.run(debug=True, port=8000)
