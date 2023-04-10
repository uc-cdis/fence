import os
import logging
import threading
import subprocess

"""Utility and helper functions used by wisecode-aws-sdk library"""

logger = logging.getLogger("wisecode-aws-sdk:utilities")


def remove_os_var(var_names):

    for var_name in var_names:
        
        if var_name in os.environ:
            del os.environ[var_name]


def get_os_vars(*args):
    result = {}

    for var_name in args:
        result[var_name] = os.environ.get(var_name, "")

    return result


class SshTunnel(threading.Thread):

    def __init__(self, local_port: int, remote_port: int, remote_host: str, ssh_config_key: str) -> None:
        # setting daemon=True means this thread will exit when main thread completes
        threading.Thread.__init__(self)
        self.local_port = str(local_port)
        self.remote_port = str(remote_port)
        self.remote_host = remote_host
        self.ssh_config_key = ssh_config_key
        self.daemon = True
        self.p = None

    def run(self) -> None:
        """Creates a ssh tunnel process that runs in the background"""
        # ssh command should run in the background until python program completes so if ever
        # finishes early, there was some error with the ssh command
        command = [
                "ssh", "-N", "-L", f"{self.local_port}:{self.remote_host}:{self.remote_port}", self.ssh_config_key
        ]
        # print(f"starting ssh tunnel with {' '.join(command)}")
        try:
            logger.debug(f"Starting ssh tunnel with {' '.join(command)}")
            self.p = subprocess.Popen(command)   
        except Exception as ex:
            logger.exception(ex)

    def stop(self) -> None:
        """Stops the running ssh tunnel process"""
        logger.debug("Stopping ssh tunnel")
        self.p.kill()
        