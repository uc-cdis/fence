from fence import app, app_config, app_register_blueprints, app_sessions, config
import argparse

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

app_config(app, config_path=args.config_path, file_name=args.config_file_name)


if config.get("MOCK_STORAGE"):
    from mock import patch
    from cdisutilstest.code.storage_client_mock import get_client

    patcher = patch("fence.resources.storage.get_client", get_client)
    patcher.start()

app_sessions(app)
app_register_blueprints(app)
app.run(debug=True, port=8000)
