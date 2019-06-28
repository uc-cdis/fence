"""
Configuration Helper Script for Local Development

Quickstart:

    python cfg_help.py create
    edit $(python cfg_help.py get)
    python run.py

  1. Create configuration file by copying example in this repo
  2. Edit the new configuration file
  3. Run fence as you normally would

Support for Multiple Configs:

    python cfg_help.py create -n google-config.yaml
    python cfg_help.py get -n google-config.yaml
    edit $(python cfg_help.py get -n google-config.yaml
    python run.py -c google-config.yaml

  1. Create another configuration file and specify new name
  2. Easily obtain the path of your new configuration
  3. Open config file in your editor with a command like
  4. Run fence and point it to the right configuration file


Fence searches specific folders for configuration files. Check fence's
settings for those paths. The LOCAL_CONFIG_FOLDER var here should be included
in the search paths.

NOTE: If using in production with wsgi.py, fence will still look for
      configuration files in the defined search paths, but will not be able
      to take in a custom configuration name by default.

      It will search for a file matching regex: *config.yaml

      You can modify the wsgi.py file to pass a file name / file path
      into the call to app_init().

"""
import argparse
import os
from os.path import expanduser
from shutil import copyfile
import sys
from gen3config import config

ROOT_DIR = os.path.dirname(os.path.realpath(__file__))
LOCAL_CONFIG_FOLDER = "{}/.gen3/fence".format(expanduser("~"))


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title="action", dest="action")

    create = subparsers.add_parser("create")
    create.add_argument(
        "-n",
        "--name",
        default="fence-config.yaml",
        help=(
            "configuration file name if you want something "
            'other than "fence-config.yaml"'
        ),
    )
    create.add_argument(
        "--config_path",
        help=(
            "Full path to a yaml config file to create. "
            "Will override/ignore name if provided."
        ),
    )

    edit = subparsers.add_parser("get")
    edit.add_argument(
        "-n",
        "--name",
        default="fence-config.yaml",
        help=(
            "configuration file name if you used something "
            'other than "fence-config.yaml"'
        ),
    )

    args = parser.parse_args()

    if args.action == "create":
        sys.stdout.write(create_config_file(args.name, args.config_path))
    elif args.action == "get":
        sys.stdout.write(get_config_file(args.name))
    else:
        raise ValueError("{} is not a recognized action.".format(args.actions))


def create_config_file(file_name, full_path=None):
    config_path = full_path or os.path.join(LOCAL_CONFIG_FOLDER, file_name)
    dir_name = os.path.dirname(config_path)
    if dir_name and not os.path.exists(dir_name):
        os.makedirs(os.path.dirname(config_path))

    copyfile(os.path.join(ROOT_DIR, "fence/config-default.yaml"), config_path)

    return config_path


def get_config_file(file_name):
    search_folders = [LOCAL_CONFIG_FOLDER]
    try:
        config_path = config.get_config_path(
            search_folders=search_folders, file_name=file_name
        )
    except IOError:
        raise IOError(
            "Config file {file_name} could not be found in the search "
            "locations: {search_folders}. Run "
            '"cfg_help.py create -n {file_name}" first.'.format(
                file_name=file_name, search_folders=search_folders
            )
        )

    return config_path


if __name__ == "__main__":
    main()
