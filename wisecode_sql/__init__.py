"""
SQLAlchemy utils
"""

import os
import logging
from typing import List, Optional, Dict

from wisecode_aws_sdk import secretsmanager
import sqlalchemy_utils
from sqlalchemy.orm import sessionmaker, scoped_session, class_mapper
from sqlalchemy import create_engine
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.query import Query
from sqlalchemy.engine.base import Engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer
from sqlalchemy import inspect


log = logging.getLogger(__name__)
SQLBaseModel = declarative_base()
sql_engine = None
sql_session = None


class SQLModel(SQLBaseModel):
    """
    SQL model base class
    """

    __abstract__ = True

    id = Column(Integer, primary_key=True, autoincrement=True)

    @classmethod
    def query(cls, sql_session: Session) -> Query:
        """
        Query from the model's table
        """

        return sql_session.query(cls)

    @classmethod
    def get_all(
        cls,
        sql_session: Session,
        start_index: bool = None,
        end_index: bool = None,
        **kwargs,
    ) -> List:
        """
        Select all from the model's table
        """

        query = cls.query(sql_session)
        if start_index and end_index:
            models = query.filter_by(**kwargs)[start_index:end_index]
        else:
            models = query.filter_by(**kwargs)

        return models

    @classmethod
    def get_all_ids(cls, sql_session: Session, model_ids: List[int]):
        """
        Gets all records from a list of IDs
        """

        return {
            model.id: model
            for model in cls.query(sql_session)
            .filter(cls.id.in_(model_ids))
            .all()
        }

    @classmethod
    def filter(
        cls,
        sql_session: Session,
        start_index: bool = None,
        end_index: bool = None,
        *args,
        **kwargs,
    ) -> List:
        """
        Select all from the model's table
        """

        query = cls.query(sql_session)
        if start_index and end_index:
            models = query.filter(*args, **kwargs)[start_index:end_index]
        else:
            models = query.filter(*args, **kwargs)

        return models

    @classmethod
    def get(cls, sql_session: Session, **kwargs):
        """
        Select the first record from the model's table
        """

        return cls.get_all(sql_session, **kwargs).first()

    @classmethod
    def get_fields(cls) -> List[str]:
        """
        Gets the model's field names
        """

        return class_mapper(cls).c.keys()

    @classmethod
    def insert(
        cls, sql_session: Session, commit: bool = True, flush: bool = False, **kwargs
    ):
        """
        Inserts a record
        """

        model = cls(**kwargs)
        sql_session.add(model)
        if flush:
            sql_session.flush()

        if commit:
            commit_transaction(sql_session)

        return model

    def api_resource(self) -> Dict:
        """
        Gets a dictionary representing the model for a JSON response
        """

        resource = {}
        for field in self.get_fields():
            resource[field] = getattr(self, field)

        return resource

    def update(
        self, sql_session: Session, commit: bool = True, flush: bool = False
    ) -> None:
        """
        Updates itself in the database
        """

        sql_session.add(self)
        if flush:
            sql_session.flush()

        if commit:
            commit_transaction(sql_session)

    def delete(
        self, sql_session: Session, commit: bool = True, flush: bool = False
    ) -> None:
        """
        Deletes itself from the database
        """

        sql_session.delete(self)
        if flush:
            sql_session.flush()

        if commit:
            commit_transaction(sql_session)

    def set_field_from_request_body(self, field, request_body):
        """
        Set's a model field if its found in the request body, and diff from the value in the request body.
        """

        if field in request_body.keys() and request_body[field] != getattr(self, field):
            setattr(self, field, request_body[field])


def sql_connection_string():
    """
    Gets the SQL connection string from env vars
    """

    if os.environ["ENVIRONMENT"] == "local":
        sql_user = os.environ["SQL_USER"]
        sql_password = os.environ["SQL_PASSWORD"]
    else:
        aws_secrets = secretsmanager.get_json_secret_value(
            os.environ["SECRET_NAME"], region=os.environ["REGION"]
        )
        sql_user = aws_secrets["username"]
        sql_password = aws_secrets["password"]

    return f"{os.environ['SQL_DRIVER']}://{sql_user}:{sql_password}@{os.environ['SQL_HOST']}:{os.environ['SQL_PORT']}/{os.environ['SQL_DATABASE']}"


def get_sql_engine(reset=False) -> Engine:
    """
    Connects to a SQL database
    """

    global sql_engine
    if not sql_engine or reset:
        sql_engine = create_engine(sql_connection_string())

    return sql_engine


def get_sql_session(reset=False) -> Session:
    """
    Returns a SQL session
    """

    global sql_session
    if not sql_session or reset:
        sql_session = scoped_session(sessionmaker(bind=get_sql_engine()))

    return sql_session


def truncate_sql_db():
    """
    Truncates SQL database tables
    """

    sql_engine = get_sql_engine()
    sql_session = get_sql_session()
    inspector = inspect(sql_engine)
    statement = "TRUNCATE TABLE "
    for table in inspector.get_table_names():
        statement += f"{table},"

    statement = f"{statement[:-1]} RESTART IDENTITY CASCADE"
    sql_session.execute(statement)
    commit_transaction(sql_session)
    log.info("Truncated the SQL database")


def commit_transaction(sql_session: Session):
    """
    Commits a SQL transaction
    """

    try:
        sql_session.commit()
        log.debug("Committed SQL transaction")
    except Exception as e:
        sql_session.rollback()
        log.debug("Failed to commit SQL transaction")
        raise e


def drop_sqldb():
    """
    Drop a SQL database
    """

    sqlalchemy_utils.drop_database(get_sql_engine().url)
    log.info("Dropped SQL database")


def create_sqldb():
    """
    Creates a SQL database
    """

    sqlalchemy_utils.create_database(get_sql_engine().url)
    log.info("Created SQL database")
