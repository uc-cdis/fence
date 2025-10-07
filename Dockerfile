# To build: docker build -t fence:latest .
# To run interactive:
#   docker run -v ~/.gen3/fence/fence-config.yaml:/var/www/fence/fence-config.yaml -v ./keys/:/fence/keys/ fence:latest
# To check running container do: docker exec -it CONTAINER bash

ARG AZLINUX_BASE_VERSION=master

# ------ Base stage ------
# For local development
FROM quay.io/cdis/amazonlinux-base:master AS gen3base

# FROM 707767160287.dkr.ecr.us-east-1.amazonaws.com/gen3/amazonlinux-base:${AZLINUX_BASE_VERSION}

LABEL name="python-nginx-build-base"
LABEL version="3.9"

ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8 \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1

# Install python build dependencies
RUN dnf update \
        --assumeyes \
    && dnf install \
        --assumeyes \
        --setopt=install_weak_deps=False \
        --setopt=tsflags=nodocs \
        git \
        python3-pip \
    && dnf clean all \
    && rm -rf /var/cache/yum

# Install pipx
RUN python3 -m pip install pipx && \
    python3 -m pipx ensurepath

# Create gen3 user
RUN groupadd -g 1000970000 gen3 && \
    useradd -m -s /bin/bash -u 1000970000 -g gen3 gen3

# Install nginx
RUN yum install nginx -y && \
    # allows nginx to run on port 80 without being root user
    # setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx && \
    chown -R gen3:gen3 /var/log/nginx && \
    # pipe nginx logs to stdout/stderr
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log && \
    mkdir -p /var/lib/nginx/tmp/client_body && \
    chown -R gen3:gen3 /var/lib/nginx/

USER gen3
# Install Poetry via pipx
RUN pipx install 'poetry<2.0'
ENV PATH="/home/gen3/.local/bin:${PATH}"
USER root

# Copy nginx config
COPY nginx.conf /etc/nginx/nginx.conf

# ------ Builder stage ------
FROM gen3base AS builder

ENV appname=fence

WORKDIR /${appname}

RUN chown -R gen3:gen3 /${appname}

USER gen3

# copy ONLY poetry artifact, install the dependencies but not the app;
# this will make sure that the dependencies are cached
COPY poetry.lock pyproject.toml /${appname}/
RUN poetry install -vv --no-root --only main --no-interaction

# Move app files into working directory
COPY --chown=gen3:gen3 . /$appname
COPY --chown=gen3:gen3 ./deployment/wsgi/wsgi.py /$appname/wsgi.py

# install the app
RUN poetry install --without dev --no-interaction

# Setup version info
RUN git config --global --add safe.directory ${appname} && COMMIT=`git rev-parse HEAD` && echo "COMMIT=\"${COMMIT}\"" > $appname/version_data.py \
    && VERSION=`git describe --always --tags` && echo "VERSION=\"${VERSION}\"" >> $appname/version_data.py



# ------ Final stage ------
FROM gen3base

ENV PATH="/${appname}/.venv/bin:$PATH"

# FIXME: Remove this when it's in the base image
ENV PROMETHEUS_MULTIPROC_DIR="/var/tmp/prometheus_metrics"
RUN mkdir -p "${PROMETHEUS_MULTIPROC_DIR}" \
    && chown gen3:gen3 "${PROMETHEUS_MULTIPROC_DIR}"

# Install ccrypt to decrypt dbgap telmetry files
RUN echo "Upgrading dnf"; \
    dnf upgrade -y; \
    echo "Installing Packages"; \
    dnf install -y \
        libxcrypt-compat-4.4.33 \
        libpq-15.0 \
        gcc \
        tar xz; \
    echo "Installing RPM"; \
    rpm -i https://ccrypt.sourceforge.net/download/1.11/ccrypt-1.11-1.src.rpm && \
    cd /root/rpmbuild/SOURCES/ && \
    tar -zxf ccrypt-1.11.tar.gz && cd ccrypt-1.11 && ./configure --disable-libcrypt && make install && make check;

COPY --chown=gen3:gen3 --from=builder /$appname /$appname

CMD ["/bin/bash", "-c", "/fence/dockerrun.bash"]
