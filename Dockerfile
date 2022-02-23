#
# Make the base image configurable so that the E2E test can use a base image
# with a prepopulated Cargo build cache to accelerate the build process.
# Use Ubuntu 16.04 because this is what the Travis CI Krill build uses.
ARG BASE_IMG=alpine:3.15

#
# -- stage 1: build krill and krillc
#
FROM ${BASE_IMG} AS build

RUN apk add rust cargo openssl-dev

WORKDIR /tmp/krill
COPY . .

# Force Cargo to use HTTP/1.1 without pipelining instead of HTTP/2 with
# multiplexing. This seems to help with various "spurious network error"
# warnings when Cargo attempts to fetch from crates.io when building this
# image on Docker Hub and GitHub Actions build machines. 
RUN CARGO_HTTP_MULTIPLEXING=false cargo build --target x86_64-alpine-linux-musl --release --locked

#
# -- stage 2: create an image containing just the binaries, configs &
#             scripts needed to run Krill, and not the things needed to build
#             it.
#
FROM alpine:3.15
COPY --from=build /tmp/krill/target/x86_64-alpine-linux-musl/release/krill /usr/local/bin/
COPY --from=build /tmp/krill/target/x86_64-alpine-linux-musl/release/krillc /usr/local/bin/
COPY --from=build /tmp/krill/target/x86_64-alpine-linux-musl/release/krillup /usr/local/bin/

# Build variables for uid and guid of user to run container
ARG RUN_USER=krill
ARG RUN_USER_UID=1012
ARG RUN_USER_GID=1012

RUN apk --no-cache add bash libgcc openssl tzdata util-linux

RUN addgroup -g ${RUN_USER_GID} ${RUN_USER} && \
    adduser -D -u ${RUN_USER_UID} -G ${RUN_USER} ${RUN_USER}

# Create the data directory structure and install a config file that uses it
WORKDIR /var/krill/data
COPY docker/krill.conf .
RUN chown -R ${RUN_USER}: .

# Install a Docker entrypoint script that will be executed when the container
# runs
COPY docker/entrypoint.sh /opt/
RUN chown ${RUN_USER}: /opt/entrypoint.sh

EXPOSE 3000/tcp

# Use Tini to ensure that krillc responds to CTRL-C when run in the
# foreground without the Docker argument "--init" (which is actually another
# way of activating Tini, but cannot be enabled from inside the Docker image).
RUN apk add --no-cache tini
# Tini is now available at /sbin/tini
ENTRYPOINT ["/sbin/tini", "--", "/opt/entrypoint.sh"]
CMD ["krill", "-c", "/var/krill/data/krill.conf"]
