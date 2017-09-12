from setuptools import setup, find_packages

setup(
    name='fence',
    install_requires=[
        "cryptography==2.0.3",
        "Flask==0.10.1",
        "Flask-Cors==3.0.2",
        "Flask-JWT-Extended==3.3.0",
        "Flask-SQLAlchemy-Session==1.1",
        "py-bcrypt==0.4",
        "psycopg2==2.6.1",
        "sqlalchemy==0.9.9",
        "userdatamodel",
        "cdispyutils",
    ],
    dependency_links=[
        "git+https://github.com/uc-cdis/flask-postgres-session.git@0.1.3#egg=flask_postgres_session",
        "git+https://github.com/uc-cdis/userdatamodel.git@1.0.2#egg=userdatamodel",
        "git+https://github.com/uc-cdis/cdis-python-utils.git@0.1.6#egg=cdispyutils",
    ],
    packages=find_packages(),
)
