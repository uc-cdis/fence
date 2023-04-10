from . import Base
from cdislogging import get_logger
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy import String, Column, MetaData, Table
from .models import *  # noqa


class SQLAlchemyDriver(object):
    def __init__(self, conn, ignore_db_error=True, **config):
        """
        setup sqlalchemy engine and session
        Args:
            conn (str): database connection
            ignore_db_error (bool): whether to ignore database setup error,
                default to True because it errors out whenever you start
                multiple servers in parallel for new db
            config (dict): engine configuration
        """

        self.engine = create_engine(conn, **config)
        self.logger = get_logger("SQLAlchemyDriver")

        Base.metadata.bind = self.engine
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        if ignore_db_error:
            try:
                self.setup_db()
            except Exception:
                self.logger.exception("Fail to setup database tables, continue anyways")
                pass
        else:
            self.setup_db()

    def setup_db(self):
        self.pre_migrate()
        Base.metadata.create_all()
        self.post_migrate()

    @property
    @contextmanager
    def session(self):
        """
        Provide a transactional scope around a series of operations.
        """
        session = self.Session()

        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_or_create(self, session, model, query, props=None):
        """
        Get or create a row
        Args:
            session: sqlalchemy session
            model: the ORM class from userdatamodel.models
            query: a dict of query parameters
            props: extra props aside from query to be added to the object on
                   creation
        Returns:
            result object of the model class
        """
        result = session.query(model).filter_by(**query).first()
        if result is None:
            args = props if props is not None else {}
            args.update(query)
            result = model(**args)
            session.add(result)
        return result

    def pre_migrate(self):
        """
        migration script to be run before create_all
        """
        if not self.engine.dialect.supports_alter:
            print(
                "This engine dialect doesn't support altering"
                " so we are not migrating even if necessary!"
            )
            return

        if not self.engine.dialect.has_table(
            self.engine, "Group"
        ) and self.engine.dialect.has_table(self.engine, "research_group"):
            print("Altering table research_group to group")
            with self.session as session:
                session.execute('ALTER TABLE research_group rename to "Group"')

    def post_migrate(self):
        md = MetaData()
        add_foreign_key_column_if_not_exist(
            table_name=User.__tablename__,
            column_name="google_proxy_group_id",
            column_type=String,
            fk_table_name=GoogleProxyGroup.__tablename__,
            fk_column_name="id",
            driver=self,
            metadata=md,
        )

        col_names = ["display_name", "phone_number"]
        for col in col_names:
            add_column_if_not_exist(
                table_name=User.__tablename__,
                column=Column(col, String),
                driver=self,
                metadata=md,
            )


def add_foreign_key_column_if_not_exist(
    table_name,
    column_name,
    column_type,
    fk_table_name,
    fk_column_name,
    driver,
    metadata,
):
    column = Column(column_name, column_type)
    add_column_if_not_exist(table_name, column, driver, metadata)
    add_foreign_key_constraint_if_not_exist(
        table_name, column_name, fk_table_name, fk_column_name, driver, metadata
    )


def drop_foreign_key_column_if_exist(table_name, column_name, driver, metadata):
    drop_foreign_key_constraint_if_exist(table_name, column_name, driver, metadata)
    drop_column_if_exist(table_name, column_name, driver, metadata)


def add_column_if_not_exist(table_name, column, driver, metadata):
    column_name = column.compile(dialect=driver.engine.dialect)
    column_type = column.type.compile(driver.engine.dialect)

    table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)
    if str(column_name) not in table.c:
        with driver.session as session:
            session.execute(
                'ALTER TABLE "{}" ADD COLUMN {} {};'.format(
                    table_name, column_name, column_type
                )
            )
            session.commit()


def drop_column_if_exist(table_name, column_name, driver, metadata):
    table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)
    if column_name in table.c:
        with driver.session as session:
            session.execute(
                'ALTER TABLE "{}" DROP COLUMN {};'.format(table_name, column_name)
            )
            session.commit()


def add_foreign_key_constraint_if_not_exist(
    table_name, column_name, fk_table_name, fk_column_name, driver, metadata
):
    table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)
    foreign_key_name = "{}_{}_fkey".format(table_name.lower(), column_name)

    if column_name in table.c:
        foreign_keys = [fk.name for fk in getattr(table.c, column_name).foreign_keys]
        if foreign_key_name not in foreign_keys:
            with driver.session as session:
                session.execute(
                    'ALTER TABLE "{}" ADD CONSTRAINT {} FOREIGN KEY({}) REFERENCES {} ({});'.format(
                        table_name,
                        foreign_key_name,
                        column_name,
                        fk_table_name,
                        fk_column_name,
                    )
                )
                session.commit()


def drop_foreign_key_constraint_if_exist(table_name, column_name, driver, metadata):
    table = Table(table_name, metadata, autoload=True, autoload_with=driver.engine)
    foreign_key_name = "{}_{}_fkey".format(table_name.lower(), column_name)

    if column_name in table.c:
        foreign_keys = [fk.name for fk in getattr(table.c, column_name).foreign_keys]
        if foreign_key_name in foreign_keys:
            with driver.session as session:
                session.execute(
                    'ALTER TABLE "{}" DROP CONSTRAINT {};'.format(
                        table_name, foreign_key_name
                    )
                )
                session.commit()
