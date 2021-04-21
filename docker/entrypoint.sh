#!/bin/bash
# Prepare the environment and config file for the Krill daemon.
# This script supports several scenarios:
#   A. The operator wants to run the Krill daemon using the default setup:
#      We have to fix a couple of things before running the Krill daemon:
#        - Krill doesn't know the FQDN at which it's HTTPS, RSYNC and RRDP
#          endpoints are published but needs to include that FQDN in data that
#          it produces. Configure it based on env var KRILL_FQDN.
#        - Krill doesn't have a default API token value, we have to supply one.
#          Generate one and announce it, if no KRILL_ADMIN_TOKEN env var was
#          supplied by the operator.
#   
#   B: The operator wants to control the Krill daemon configuration themselves.
#      They do this by Docker mounting their own krill.conf over the
#      /var/krill/data/krill.conf path.
#
#   C: The operator wants to run some other command in the container, e.g.
#      krill_admin.
#
set -e
KRILL_CONF=/var/krill/data/krill.conf
KRILL_FQDN="${KRILL_FQDN:-localhost:3000}"
KRILL_ADMIN_TOKEN="${KRILL_ADMIN_TOKEN:-None}"
KRILL_LOG_LEVEL="${KRILL_LOG_LEVEL:-warn}"
KRILL_USE_TA="${KRILL_USE_TA:-false}"

MAGIC="# DO NOT TOUCH, THIS LINE IS MANAGED BY DOCKER KRILL"
LOG_PREFIX="docker-krill:"

log_warning() {
    echo >&2 "${LOG_PREFIX} Warning! $*"
}

log_info() {
    echo "${LOG_PREFIX} $*"
}

if [ "$1" == "krill" ]; then
    # Does the operator want to use their own API token? If so they must
    # supply the KRILL_ADMIN_TOKEN env var.
    if [ "${KRILL_ADMIN_TOKEN}" == "None" ]; then
        # Generate a unique hard to guess authorization token and export it
        # so that the Krill daemon uses it (unless overridden by the Krill
        # daemon config file). Only do this if the operator didn't already
        # supply a token when launching the Docker container.
        export KRILL_ADMIN_TOKEN=$(uuidgen)
    fi

    # Announce the token in the Docker logs so that clients can obtain it.
    log_info "Securing Krill daemon with token ${KRILL_ADMIN_TOKEN}"

    log_info "Configuring ${KRILL_CONF} .."
    # If the config file was persisted and the container was recreated with
    # different arguments to docker run there may still be some lines in the
    # config file that we added before which are now no longer correct. Remove
    # any lines that we added.
    if ! sed -i "/.\\+${MAGIC}/d" ${KRILL_CONF} 2>/dev/null; then
        log_warning "Cannot write to ${KRILL_CONF}. You can ignore this warning if you mounted your own config file over ${KRILL_CONF}."
    else
        # Append to the default Krill config file to direct clients of the
        # RSYNC and RRDP endpoints to the correct FQDN. We cannot know know the
        # FQDN which clients use to reach us so the operator must inform this
        # script via a "-e KRILL_FQDN=some.domain.name" argument to
        # "docker run".
        cat << EOF >> ${KRILL_CONF}
log_level   = "${KRILL_LOG_LEVEL}" ${MAGIC}
EOF

        log_info "Dumping ${KRILL_CONF} config file"
        cat ${KRILL_CONF}
        log_info "End of dump"
    fi
fi

# Launch the command supplied either by the default CMD (krill) in the
# Dockerfile or that given by the operator when invoking Docker run. Use exec
# to ensure krill runs as PID 1 as required by Docker for proper signal
# handling. This also allows this Docker image to be used to run krill_admin
# instead of krill.
exec "$@"
