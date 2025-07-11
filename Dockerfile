# To build: docker build -t fence:latest .
# To run interactive:
#   docker run -v ~/.gen3/fence/fence-config.yaml:/var/www/fence/fence-config.yaml -v ./keys/:/fence/keys/ fence:latest
# To check running container do: docker exec -it CONTAINER bash

ARG AZLINUX_BASE_VERSION=master

# ------ Base stage ------
FROM quay.io/cdis/python-nginx-al:${AZLINUX_BASE_VERSION} AS base
# Comment this in, and comment out the line above, if quay is down
# FROM 707767160287.dkr.ecr.us-east-1.amazonaws.com/gen3/python-nginx-al:${AZLINUX_BASE_VERSION} as base

ENV appname=fence

WORKDIR /${appname}
RUN chown -R gen3:gen3 /${appname}
RUN mkdir -p /amanuensis 


# ------ Builder stage ------
FROM base AS builder

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
FROM base

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
