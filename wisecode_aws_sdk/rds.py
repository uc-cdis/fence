import time
import boto3
import typing
import concurrent.futures
import postgresql.driver as pg_driver

from wisecode_aws_sdk import utilities


"""Module with functions that help with interaction with the AWS RDS service"""


def import_s3_object_to_table(bucket_name: str, key: str, table_name: str, 
    db_connection: pg_driver.pq3.Connection, pg_copy_opts: str, 
    columns: typing.List[str] = None,) -> str:
    """Runs the aws_s3.table_import_s3 stored proc on a RDS db instance with the
    provided information to import a S3 object into a Postgres table.

    :param bucket_name: S3 bucket object to import is in
    :type bucket_name: str
    :param key: Key name of object to import
    :type key: str
    :param table_name: Name of the Postgres table to import object to
    :type table_name: str
    :param db_connection: A py-postgresql connection to the RDS database to import data into
    :type db_connection: pg_driver.pq3.Connection
    :param pg_copy_opts: Text string containing arguments for the Postgres COPY command that specify how the data is to be copied into the destination table
    :type pg_copy_opts: str
    :param columns: List of column names in which to copy data to, defaults to None (which means load all columns)
    :type columns: typing.List[str]
    :return: A message with how many rows were inserted into the target table
    :rtype: str
    """
    
    if columns is None:
        cols = ""
    else:
        cols = ",".join(columns)

    copy_proc = db_connection.prepare(
        """SELECT aws_s3.table_import_from_s3(
            $1,
            $2,
            $3,
            aws_commons.create_s3_uri($4, $5, 'us-east-2')
        )"""
    )
    resp = copy_proc(
        table_name,
        cols,
        pg_copy_opts,
        bucket_name,
        key
    )

    return resp[0][0]


def import_s3_objects_to_tables(objects: typing.List[typing.Dict[str, object]], 
    db_connection: pg_driver.pq3.Connection, max_workers: int = 10) -> typing.List[str]:
    """Runs the aws_s3.table_import_s3 stored proc on a RDS db instance with the
    provided information to import a list of S3 objects into RDS Postgres tables.

    :param objects: List of object dictionaries that contain the S3 object and postgres table information in the keys "bucket_name", "key", "table_name", "pg_copy_opts", and "columns"
    :type objects: typing.Dict[str, object]
    :param db_connection: A py-postgresql connection to the RDS database to import data into
    :type db_connection: pg_driver.pq3.Connection
    :param max_workers: Number of threads to use to do the imports, defaults to 10
    :type max_workers: int, optional
    :return: A list of the messages returned from each aws_s3.table_import_s3 stored proc run
    :rtype: typing.List[str]
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        exec_futures = [
            executor.submit(
                import_s3_object_to_table,
                obj["bucket_name"],
                obj["key"],
                obj["table_name"],
                db_connection.clone(),
                obj["pg_copy_opts"],
                columns=obj["columns"]
            ) for obj in objects
        ]

        results = [future.result() for future in exec_futures]

    return results
    

def get_db_endpoint(database_identifier: str, session: boto3.Session = None) -> typing.Tuple[str, str]:
    """Return the requested RDS instance's endpoint and port. Returns as a tuple structed like (endpoint, port).

    :param database_identifier: Name of the RDS instance
    :type database_identifier: str
    :param session: boto3 Session instance to use when accessing RDS, defaults to None
    :type session: boto3.Session, optional
    :return: A tuple with the endpoint and port structured like (endpoint, port)
    :rtype: typing.Tuple[str, str]
    """
    if not session:
        session = boto3._get_default_session()
    
    client = session.client("rds")
    resp = client.describe_db_instances(DBInstanceIdentifier=database_identifier)
    # returns are a list but currently we only ever have one RDS instance per identifier
    db_info = resp["DBInstances"][0]
    endpoint = db_info["Endpoint"]

    return endpoint["Address"], endpoint["Port"]


def connect_to_rds_db(database_identifier: str, user: str, password: str, database: str,
     session: boto3.Session = None) -> pg_driver.pq3.Connection:
    """Connects to the desired RDS instance's Postgres database

    :param database_identifier: Name of the RDS instance the postgres database is on
    :type database_identifier: str
    :param user: Postgres database user to use
    :type user: str
    :param password: Postgres database user's password
    :type password: str
    :param database: Postgres database to connect to
    :type database: str
    :param session: boto3 Session instance to use when accessing RDS, defaults to None
    :type session: boto3.Session, optional
    :return: A py-postgresql database connection object
    :rtype: pg_driver.pq3.Connection
    """
    if not session:
        session = boto3._get_default_session()

    db_host, db_port = get_db_endpoint(database_identifier, session=session)

    return pg_driver.connect(
        user=user,
        host=db_host,
        port=db_port,
        database=database,
        password=password
    )


def connect_to_rds_db_with_sshtunnel(database_identifier: str, ssh_config_key: str, host: str, user: str, password: str,
    database: str, local_port: int = 5432, session: boto3.Session = None) -> typing.Tuple[pg_driver.pq3.Connection, utilities.SshTunnel]:
    """Connects to the desired RDS instance's Postgres database using the configured .ssh/config bastion host

    :param database_identifier: Name of the RDS instance the postgres database is on
    :type database_identifier: str
    :param ssh_config_key: Name of the bastion host using configured in the .ssh/config file
    :type ssh_config_key: str
    :param user: Postgres database user to use
    :type user: str
    :param password: Postgres database user's password
    :type password: str
    :param database: Postgres database to connect to
    :type database: str
    :param local_port: Local port to forward traffic from to the RDS instance through the bastion host, defaults to 5432
    :type local_port: int, optional
    :param session: boto3 Session instance to use when accessing RDS, defaults to None
    :type session: boto3.Session, optional
    :return: A tuple with the py-postgresql database connection object and a SshTunnel object that is running in the background
    :rtype: typing.Tuple[pg_driver.pq3.Connection, utilities.SshTunnel]
    """
    if not session:
        session = boto3._get_default_session()

    db_host, db_port = get_db_endpoint(database_identifier, session=session)
    tunnel = utilities.SshTunnel(local_port, db_port, db_host, ssh_config_key)
    tunnel.start()
    # let ssh tunnel get setup
    time.sleep(2)

    return pg_driver.connect(
        user=user,
        host=host,
        port=local_port,
        database=database,
        password=password
    ), tunnel