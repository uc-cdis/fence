ARG AZLINUX_BASE_VERSION=master

# Base stage with python-build-base
FROM quay.io/cdis/python-build-base:${AZLINUX_BASE_VERSION} as base

# Comment this in, and comment out the line above, if quay is down
# FROM 707767160287.dkr.ecr.us-east-1.amazonaws.com/gen3/python-build-base:${AZLINUX_BASE_VERSION} as base

ENV appname=fence
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1

WORKDIR /${appname}

# create gen3 user
# Create a group 'gen3' with GID 1000 and a user 'gen3' with UID 1000
RUN groupadd -g 1000 gen3 && \
    useradd -m -s /bin/bash -u 1000 -g gen3 gen3  && \
    chown -R gen3:gen3 /$appname && \
    mkdir -p /var/www/$appname && \
    chown -R gen3:gen3 /var/www/$appname && \
    chown -R gen3:gen3 /venv


# Builder stage
FROM base as builder

USER gen3


RUN python -m venv /venv


COPY poetry.lock pyproject.toml /${appname}/

RUN pip install poetry && \
    poetry install -vv --only main --no-interaction

COPY --chown=gen3:gen3 . /$appname
COPY --chown=gen3:gen3 ./deployment/wsgi/wsgi.py /$appname/wsgi.py

# Run poetry again so this app itself gets installed too
RUN poetry install --without dev --no-interaction

RUN git config --global --add safe.directory /${appname} && COMMIT=`git rev-parse HEAD` && echo "COMMIT=\"${COMMIT}\"" > /$appname/version_data.py \
    && VERSION=`git describe --always --tags` && echo "VERSION=\"${VERSION}\"" >> /$appname/version_data.py

# Final stage
FROM base

COPY --from=builder /venv /venv
COPY --from=builder /$appname /$appname

# install tar
RUN yum install tar -y

# install nginx
RUN yum install nginx -y

RUN setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx

# chown nginx directories
RUN chown -R gen3:gen3 /var/log/nginx

# pipe nginx logs to stdout and stderr
RUN ln -sf /dev/stdout /var/log/nginx/access.log && ln -sf /dev/stderr /var/log/nginx/error.log

# create /var/lib/nginx/tmp/client_body to allow nginx to write to fence
RUN mkdir -p /var/lib/nginx/tmp/client_body
RUN chown -R gen3:gen3 /var/lib/nginx/

# copy nginx config
COPY ./deployment/nginx/nginx.conf /etc/nginx/nginx.conf


# Switch to non-root user 'gen3' for the serving process
USER gen3

RUN source /venv/bin/activate

ENV PYTHONUNBUFFERED=1 \
PYTHONIOENCODING=UTF-8


CMD ["/fence/dockerrun.bash"]
