# To build: docker build -t fence:latest .
# To run interactive:
#   docker run -v ~/.gen3/fence/fence-config.yaml:/var/www/fence/fence-config.yaml -v ./keys/:/fence/keys/ fence:latest
# To check running container do: docker exec -it CONTAINER bash

ARG AZLINUX_BASE_VERSION=feat_python-nginx

# ------ Base stage ------
FROM quay.io/cdis/python-nginx-al:${AZLINUX_BASE_VERSION} AS base

# Comment this in, and comment out the line above, if quay is down
# FROM 707767160287.dkr.ecr.us-east-1.amazonaws.com/gen3/python-nginx-al:${AZLINUX_BASE_VERSION} as base

ENV appname=fence

WORKDIR /${appname}

RUN chown -R gen3:gen3 /${appname}

# ------ Builder stage ------
FROM base AS builder

# Install just the deps without the code as it's own step to avoid redoing this on code changes
COPY poetry.lock pyproject.toml /${appname}/
RUN poetry lock -vv --no-update \
    && poetry install -vv --only main --no-interaction

# Move app files into working directory
COPY --chown=gen3:gen3 . /$appname
COPY --chown=gen3:gen3 ./deployment/wsgi/wsgi.py /$appname/wsgi.py

# Do the install again incase the app itself needs install
RUN poetry lock -vv --no-update \
    && poetry install -vv --only main --no-interaction

ENV PATH="$(poetry env info --path)/bin:$PATH"

# Setup version info
RUN git config --global --add safe.directory /${appname} && COMMIT=`git rev-parse HEAD` && echo "COMMIT=\"${COMMIT}\"" > /$appname/version_data.py \
    && VERSION=`git describe --always --tags` && echo "VERSION=\"${VERSION}\"" >> /$appname/version_data.py

# install tar
RUN yum install tar -y
# do we need to untar jwt-keys?

#Set python with python3
RUN echo 'alias python="python3"' >> ~/.bashrc && source ~/.bashrc;


# ------ Final stage ------
FROM base

COPY --chown=gen3:gen3 --from=builder /$appname /$appname

CMD ["poetry", "run", "gunicorn", "-c", "deployment/wsgi/gunicorn.conf.py"]
