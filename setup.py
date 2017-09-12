from setuptools import setup, find_packages

setup(
    name='fence',
    install_requires=[
        "Flask==0.10.1",
        "psycopg2==2.6.1",
        "Flask-Cors==3.0.2",
        "userdatamodel",
        "py-bcrypt==0.4",
        "sqlalchemy==0.9.9",
        "Flask-SQLAlchemy-Session==1.1",
        "Flask-JWT-Extended==3.3.0",
    ],
    dependency_links=[
        "git+https://github.com/uc-cdis/flask-postgres-session.git@0.1.3#egg=flask_postgres_session",
        "git+https://github.com/uc-cdis/userdatamodel.git@1.0.2#egg=userdatamodel",
    ],
    packages=find_packages(),
)
