"""Contains functions for interating with the AWS DynamoDB service"""
import boto3
import typing


def get_table(name: str, session: boto3.Session = None):
    """Returns a boto3 DynamoDB.Table of the name requested for an AWS 
    DynamoDB table. Full documentation on this Table class is located
    here, https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/dynamodb.html#DynamoDB.Table

    :param name: Name of the AWS DynamoDB Table to return
    :type name: str
    :param session: A boto3.Session class instance, defaults to None. If None is give, the boto3 default session is created
    :type session: boto3.Session, optional
    :return: Boto3 DynamoDB.Table class instance of the AWS DynamoDB table requested
    :rtype: DynamoDB.Table
    """
    if not session:
        session = boto3._get_default_session()

    dynamodb = session.resource("dynamodb")

    return dynamodb.Table(name)


def write_items_to_table(table, items: typing.List[typing.Dict[str, object]]) -> None:
    """Function writes a list of items to the give DynamoDB.Table class instance
    provided. Is an efficient way to write many items to a single AWS Dynamodb 
    table at once. Function is just an abstraction of the DynamoDB.Table
    batch_writer() method.

    :param table: DynamoDB.Table class instance to write items to
    :type table: DynamoDB.Table
    :param items: List of dictionaries that represent the Items to write to DynamoDB table
    :type items: typing.List[typing.Dict[str, object]]
    """
    with table.batch_writer() as writer:
        for item in items:
            writer.put_item(Item=item)
