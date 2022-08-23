# This is a multi-stage Dockerfile, with a selectable first stage. With this
# approach we get:
#
#   1. Separation of dependencies needed to build our app in the 'build' stage
#      and those needed to run our app in the 'final' stage, as we don't want
#      the build-time dependencies to be included in the final Docker image.
#
#   2. Support for either building our app for the architecture of the base
#      image using MODE=build (the default) or for externally built app
#      binaries (e.g. cross-compiled) using MODE=copy.
#
# In total there are four stages consisting of:
#   - Two possible first stages: 'build' or 'copy'.
#   - A special 'source' stage which selects either 'build' or 'copy' as the
#     source of binaries to be used by ...
#   - The 'final' stage.


###
### ARG DEFINITIONS ###########################################################
###

# This section defines arguments that can be overriden on the command line
# when invoking `docker build` using the argument form:
#
#   `--build-arg <ARGNAME>=<ARGVALUE>`.

# MODE
# ====
# Supported values: build (default), copy
#
# By default this Dockerfile will build our app from sources. If the sources
# have already been (cross) compiled by some external process and you wish to
# use the resulting binaries from that process, then:
#
#   1. Create a directory on the host called 'dockerbin/$TARGETPLATFORM'
#      containing the already compiled app binaries (where $TARGETPLATFORM
#      is a special variable set by Docker BuiltKit).
#   2. Supply arguments `--build-arg MODE=copy` to `docker build`.
ARG MODE=build


# BASE_IMG
# ========
#
# Only used when MODE=build.
ARG BASE_IMG=alpine:3.15


# CARGO_ARGS
# ==========
#
# Only used when MODE=build.
#
# This ARG is intended for use by the Krill E2E test so that if needed it can
# control the features enabled when compiling Krill.
ARG CARGO_ARGS


###
### BUILD STAGES ##############################################################
###


# -----------------------------------------------------------------------------
# Docker stage: build
# -----------------------------------------------------------------------------
#
# Builds our app binaries from sources.
FROM ${BASE_IMG} AS build
ARG CARGO_ARGS

RUN apk --no-cache add rust cargo openssl-dev

WORKDIR /tmp/build
COPY . .

# `CARGO_HTTP_MULTIPLEXING` forces Cargo to use HTTP/1.1 without pipelining
# instead of HTTP/2 with multiplexing. This seems to help with various
# "spurious network error" warnings when Cargo attempts to fetch from crates.io
# when building this image on Docker Hub and GitHub Actions build machines.
#
# `cargo install` is used instead of `cargo build` because it places just the
# binaries we need into a predictable output directory. We can't control this
# with arguments to cargo build as `--out-dir` is unstable and contentious and
# `--target-dir` still requires us to know which profile and target the
# binaries were built for. By using `cargo install` we can also avoid needing
# to hard-code the set of binary names to copy so that if we add or remove
# built binaries in future this will "just work". Note that `--root /tmp/out`
# actually causes the binaries to be placed in `/tmp/out/bin/`. `cargo install`
# will create the output directory for us.
RUN CARGO_HTTP_MULTIPLEXING=false cargo install \
  --target x86_64-alpine-linux-musl \
  --locked \
  --path . \
  --root /tmp/out/ \
  ${CARGO_ARGS}


# -----------------------------------------------------------------------------
# Build stage: copy
# -----------------------------------------------------------------------------
# Only used when MODE=copy.
#
# Copy binaries from the host directory 'dockerbin/$TARGETPLATFORM' directory
# into this build stage to the same predictable location that binaries would be
# in if MODE were 'build'.
#
# Requires that `docker build` be invoked with variable `DOCKER_BUILDKIT=1` set
# in the environment. This is necessary so that Docker will skip the unused
# 'build' stage and so that the magic $TARGETPLATFORM ARG will be set for us.
FROM ${BASE_IMG} AS copy
ARG TARGETPLATFORM
ONBUILD COPY dockerbin/$TARGETPLATFORM /tmp/out/bin/


# -----------------------------------------------------------------------------
# Docker stage: source
# -----------------------------------------------------------------------------
# This is a "magic" build stage that "labels" a chosen prior build stage as the
# one that the build stage after this one should copy application binaries
# from.
FROM ${MODE} AS source


# -----------------------------------------------------------------------------
# Docker stage: final
# -----------------------------------------------------------------------------
# Create an image containing just the binaries, configs & scripts needed to run
# our app, and not the things needed to build it.
#
# The previous build stage from which binaries are copied is controlled by the
# MODE ARG (see above).
FROM alpine:3.15 AS final

# Copy binaries from the 'source' build stage into the image we are building
COPY --from=source /tmp/out/bin/* /usr/local/bin/

# Build variables for uid and guid of user to run container
ARG RUN_USER=krill
ARG RUN_USER_UID=1012
ARG RUN_USER_GID=1012

# Install required runtime dependencies
RUN apk --no-cache add bash libgcc openssl tini tzdata util-linux

# Create the user and group to run the application as
RUN addgroup -g ${RUN_USER_GID} ${RUN_USER} && \
    adduser -D -u ${RUN_USER_UID} -G ${RUN_USER} ${RUN_USER}

# Create the data directory structure and install a config file that uses it
WORKDIR /var/krill/data
COPY docker/krill.conf .
RUN chown -R ${RUN_USER}: .

# Install a Docker entrypoint script that will be executed when the container
# runs.
COPY docker/entrypoint.sh /opt/
RUN chown ${RUN_USER}: /opt/entrypoint.sh

# Switch to our applications user
USER $RUN_USER_UID

# Hint to operators the TCP port that the application in this image listens on
# (by default).
EXPOSE 3000/tcp

# Use Tini to ensure that our application responds to CTRL-C when run in the
# foreground without the Docker argument "--init" (which is actually another
# way of activating Tini, but cannot be enabled from inside the Docker image).
ENTRYPOINT ["/sbin/tini", "--", "/opt/entrypoint.sh"]
CMD ["krill", "-c", "/var/krill/data/krill.conf"]
