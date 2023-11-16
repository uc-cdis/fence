ARG AZLINUX_BASE_VERSION=master

# Base stage with python-build-base
FROM 707767160287.dkr.ecr.us-east-1.amazonaws.com/gen3/python-build-base:${AZLINUX_BASE_VERSION} as base

ENV appname=fence
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    PYSETUP_PATH="/opt/pysetup" \
    VENV_PATH="/opt/pysetup/.venv"

ENV PATH="$POETRY_HOME/bin:$VENV_PATH/bin:$PATH"

WORKDIR /${appname}

# Builder stage
FROM base as builder

COPY poetry.lock pyproject.toml /${appname}/
RUN pip install poetry && \
    poetry install --no-dev

COPY --chown=gen3:gen3 . /$appname
COPY --chown=gen3:gen3 ./deployment/wsgi/wsgi.py /$appname/wsgi.py


RUN git config --global --add safe.directory /${appname} && COMMIT=`git rev-parse HEAD` && echo "COMMIT=\"${COMMIT}\"" > /$appname/version_data.py \
    && VERSION=`git describe --always --tags` && echo "VERSION=\"${VERSION}\"" >> /$appname/version_data.py

# Final stage
FROM base

RUN pip install gunicorn

COPY --from=builder /$appname /$appname

# create gen3 user
# Create a group 'gen3' with GID 1000 and a user 'gen3' with UID 1000
RUN groupadd -g 1000 gen3 && \
    useradd -m -s /bin/bash -u 1000 -g gen3 gen3  && \
    chown -R gen3:gen3 /$appname

# Switch to non-root user 'gen3' for the serving process
# USER gen3

# update PATH to include poetry
ENV PATH="$POETRY_HOME/bin:$PATH"

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8

CMD ["gunicorn", "-c", "deployment/wsgi/gunicorn.conf.py"]
