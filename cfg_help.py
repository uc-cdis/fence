"""
Configuration Helper Script for Local Development

Quickstart:

  1. Create configuration file by copying example in this repo:
        python cfg_help.py create -n fence_default.yaml

  2. Run fence and point it to the right configuration file:
        python run.py -c fence_default.yaml

Extras:

  - Easily obtain the path of your configuration:
        python cfg_help.py get -n fence_default.yaml

  - Open config file in your editor with a command like:
        sudo edit $(python cfg_help.py get -n fence_default.yaml)

  - Create more configs:
        python cfg_help.py create -n fence_google.yaml

Fence searches specific folders for configuration files. Check fence's
settings for those paths. The LOCAL_CONFIG_FOLDER var here should be included
in the search paths.
"""
import os
import argparse
from shutil import copyfile
import sys

ROOT_DIR = os.path.dirname(os.path.realpath(__file__))
LOCAL_CONFIG_FOLDER = '/etc/gen3/fence'


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='action', dest='action')

    create = subparsers.add_parser('create')
    create.add_argument(
        '-n', '--name', default='config.yaml', help='configuration file name if you want something '
        'other than "config.yaml"')

    edit = subparsers.add_parser('get')
    edit.add_argument(
        '-n', '--name', default='config.yaml', help='configuration file name if you used something '
        'other than "config.yaml"')

    args = parser.parse_args()

    if args.action == 'create':
        sys.stdout.write(create_config_file(args.name))
    elif args.action == 'get':
        sys.stdout.write(get_config_file(args.name))
    else:
        pass


def create_config_file(file_name):
    config_path = os.path.join(LOCAL_CONFIG_FOLDER, file_name)
    if not os.path.exists(os.path.dirname(config_path)):
        os.makedirs(os.path.dirname(config_path))

    copyfile(os.path.join(ROOT_DIR, 'config.example.yaml'), config_path)

    return config_path


def get_config_file(file_name):
    search_folders = [LOCAL_CONFIG_FOLDER]
    try:
        config_path = get_config_path(search_folders, file_name=file_name)
    except IOError:
        raise IOError(
            'Config file {file_name} could not be found in the search '
            'locations: {search_folders}. Run '
            '"cfg_help.py create -n {file_name}" first.'
            .format(file_name=file_name, search_folders=search_folders))

    return config_path


def get_config_path(search_folders, file_name='config.yaml'):
    for folder in search_folders:
        config_path = os.path.join(folder, file_name)
        if os.path.exists(config_path):
            return config_path

    # if we haven't returned a path by now, fence couldn't find the config
    raise IOError(
        'Could not find config.yaml. Searched in the following locations: '
        '{}'.format(str(search_folders)))


if __name__ == '__main__':
    main()
