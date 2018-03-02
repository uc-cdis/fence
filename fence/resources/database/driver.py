from fence.models import Base
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager
from sqlalchemy import create_engine


class SQLAlchemyDriver(object):
    def __init__(self, conn, **config):
        self.engine = create_engine(conn, **config)

        Base.metadata.bind = self.engine
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.pre_migrate()
        Base.metadata.create_all()

    @property
    @contextmanager
    def session(self):
        '''
        Provide a transactional scope around a series of operations.
        '''
        session = self.Session()
        yield session

        try:
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_or_create(self, session, model, query, props=None):
        '''
        Get or create a row
        Args:
            session: sqlalchemy session
            model: the ORM class from fence.models
            query: a dict of query parameters
            props: extra props aside from query to be added to the object on
                   creation
        Returns:
            result object of the model class
        '''
        result = session.query(model).filter_by(**query).first()
        if result is None:
            args = props if props is not None else {}
            args.update(query)
            result = model(**args)
            session.add(result)
        return result

    def pre_migrate(self):
        '''
        migration script to be run before create_all
        '''
        if not self.engine.dialect.supports_alter:
            print(
                "This engine dialect doesn't support altering"
                " so we are not migrating even if necessary!")
            return

        if (not self.engine.dialect.has_table(self.engine, 'Group') and
                self.engine.dialect.has_table(self.engine, 'research_group')):
            print("Altering table research_group to group")
            with self.session as session:
                session.execute('ALTER TABLE research_group rename to "Group"')
