#
# -- stage 1: build krilld and krill_admin
# Use Ubuntu 16.04 because this is what the Travis CI Krill build uses.
#
FROM ubuntu:16.04 AS builder

# Install Rust
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        libssl-dev \
        pkg-config

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH "/root/.cargo/bin:$PATH"

# Build the Krill daemon and krill_admin CLI tool
# Due to https://github.com/rust-lang/cargo/issues/2644#issuecomment-526931209
# we do a hacky first step to build dependencies first so that we don't have to
# COPY directories and files individually because COPY . . causes the entire
# build to be repeated if any file is changed, even if it was a docker/ file
# that only affects the second stage of the build.
WORKDIR /tmp/krill
COPY Cargo.toml .
COPY yarn.lock .
COPY client client
COPY commons commons
COPY daemon daemon
COPY pubc pubc
COPY pubd pubd
RUN cargo build --release --bin krilld --bin krill_admin

#
# -- stage 2: create an image containing just the binaries, configs &
#             scripts needed to run Krill, and not the things needed to build
#             it.
#
FROM ubuntu:16.04
COPY --from=builder /tmp/krill/target/release/krilld /usr/local/bin/
COPY --from=builder /tmp/krill/target/release/krill_admin /usr/local/bin/

# Build variables for uid and guid of user to run container
ARG RUN_USER=krill
ARG RUN_USER_UID=1012
ARG RUN_USER_GID=1012

# Install openssl as Krill depends on it.
# Install uuid-runtime for generating an authorization token on startup.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        openssl \
        uuid-runtime

RUN groupadd -g ${RUN_USER_GID} ${RUN_USER} && \
    useradd -g ${RUN_USER_GID} -u ${RUN_USER_UID} ${RUN_USER}

# Create the data directory structure and install a config file that uses it
WORKDIR /var/krill/data
COPY docker/krill.conf .
RUN chown -R ${RUN_USER}: .

# Install a Docker entrypoint script that will be executed when the container
# runs
COPY docker/entrypoint.sh /opt/
RUN chown ${RUN_USER}: /opt/entrypoint.sh

EXPOSE 3000/tcp

ENTRYPOINT ["/opt/entrypoint.sh"]
CMD ["krilld", "-c", "/var/krill/data/krill.conf"]
