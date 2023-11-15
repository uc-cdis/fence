ARG AZLINUX_BASE_VERSION=master

# Base stage with python-build-base
FROM 707767160287.dkr.ecr.us-east-1.amazonaws.com/gen3/python-build-base:${AZLINUX_BASE_VERSION} as base

ENV appname=fence
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1

# Create a non-root user 'gen3' in the base stage itself
RUN useradd -ms /bin/bash gen3

# Builder stage
FROM base as builder

# Switch to non-root user 'gen3' for the build process
USER gen3

WORKDIR /home/gen3/$appname

COPY poetry.lock pyproject.toml /home/gen3/$appname/
RUN pip install --upgrade poetry \
    && poetry install --without dev --no-interaction

COPY . /home/gen3/$appname
COPY ./deployment/wsgi/wsgi.py /home/gen3/$appname/wsgi.py
RUN poetry install --without dev --no-interaction

RUN COMMIT=`git rev-parse HEAD` && echo "COMMIT=\"${COMMIT}\"" > /home/gen3/$appname/version_data.py \
    && VERSION=`git describe --always --tags` && echo "VERSION=\"${VERSION}\"" >> /home/gen3/$appname/version_data.py

# Final stage
FROM base

# Copy the virtual environment and application code from the builder stage
COPY --from=builder /home/gen3/venv /home/gen3/venv
COPY --from=builder /home/gen3/$appname /home/gen3/$appname

# Switch to non-root user 'gen3' for the serving process
USER gen3

WORKDIR /home/gen3/$appname

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8

CMD ["gunicorn", "-c", "deployment/wsgi/gunicorn.conf.py"]
