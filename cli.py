"""
Command line interface
"""

import logging

import click
from dotenv import load_dotenv
import requests
from sqlalchemy.exc import ProgrammingError
import wisecode_sql

load_dotenv()

from fence import utils


log = logging.getLogger(__name__)


utils.configure_logging()


@click.group()
def command_group() -> None:
    """
    Click command group
    """


@click.command()
def create_sqldb() -> None:
    """
    Creates the SQL database
    """

    try:
        wisecode_sql.create_sqldb()
    except ProgrammingError:
        log.info("SQL database exists")


@click.command()
def drop_sqldb() -> None:
    """
    Drops the SQL database
    """

    wisecode_sql.drop_sqldb()


@click.command()
def truncate_sqldb() -> None:
    """
    Truncates the SQL tables
    """

    wisecode_sql.truncate_sql_db()


@click.command()
def setup_sqldb() -> None:
    """
    Sets up the SQL database
    """

    utils.set_up_sqldb()


@click.command()
@click.option("--email", "-e", required=True, type=str)
@click.option("--password", "-p", required=True, type=str)
def create_cognito_user(email, password) -> None:
    """
    Create a Cognito user
    """

    cognito_client = utils.get_cognito_client()
    utils.create_cognito_user(cognito_client, email, password)
    log.info(f"Created Cognito user with email {email}")


@click.command()
@click.option("--email", "-e", required=True, default="drodgers@wisecode.ai", type=str)
@click.option("--password", "-p", required=True, default="WISEcode1!", type=str)
def cognito_user_jwt(email, password) -> None:
    """
    Get a Cogntio user JWT
    """

    jwt = utils.cognito_user_jwt(email, password)
    log.info(f"\n\nCognito JWT\n\n{jwt}\n\n")


@click.command()
@click.option("--email", "-e", default="drodgers@wisecode.ai", type=str)
@click.option("--password", "-p", default="WISEcode1!", required=True, type=str)
def call_login(email, password) -> None:
    """
    Calls the WISEcodePlatform login endpoint
    """

    response = requests.post(
            f"{utils.get_env_var('FENCE_BASE_URL')}login/wisecode", 
            headers={
                "Content-Type": "application/json",
            },
            json={
                "username": email,
                "password": password
            }
    )
    log.info(f"Login response code {response.status_code} and JSON {response.json()}")


def main() -> None:
    """
    Run Click app
    """

    for command in [
        call_login, 
        create_sqldb, 
        setup_sqldb, 
        drop_sqldb, 
        truncate_sqldb, 
        create_cognito_user, 
        cognito_user_jwt
    ]:
        command_group.add_command(command)

    command_group()


if __name__ == "__main__":
    main()
