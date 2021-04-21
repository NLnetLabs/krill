################################################################################
### Role mappings
################################################################################

# Note: mapping of roles to users is not defined here.
#
# Users that authenticate using .htpasswd credentials a role should be assigned
# to them in the mappings.polar or other .polar file using actor_has_role() (see
# below).

# Users that authenticate with an OpenID Connect provider should have a role
# assigned to them via an attribute extracted from the OpenID Connect provider
# response, or via an explicit actor_has_role() assignment as mentioned above.


################################################################################
### Role definitions
################################################################################

# All roles have the right to login:
# ----------------------------------
# Actors with a role, any role, can login to the UI and are permitted to use the
# REST API. This is because roles are only assigned to actors if they were able
# to authenticate and a role mapping exists for them. Conversely, actors that
# are able to authenticate but for whom no role mapping exists, will not be
# permitted to login to the UI or to use the REST API.
#

# If called with Option::None then some_role will be the Oso value nil.
# Otherwise some_role should be a string that we want to contain some value
# other than whitespace, so we check that it is non-empty after trimming any
# leading and/or trailing whitespace.
role_allow(some_role, action: Permission) if
    not some_role = nil and
    not some_role.trim().is_empty() and
    action = LOGIN;

### TEST: [
# Actors with a role can login.
?= role_allow("some role", LOGIN);
# Conversely, actors without a role cannot do anything.
?= not role_allow(nil, LOGIN);
?= not role_allow("", LOGIN);
?= not role_allow("  ", LOGIN);
?= not role_allow(nil, nil);
?= not role_allow(nil, _);
### ]


# The admin role has the right to do anything with any resource:
# --------------------------------------------------------------
role_allow("admin", _action: Permission);

### TEST: [
?= role_allow("admin", _);
?= not role_allow("admin", "take over the world");
?= role_allow("admin", CA_CREATE);
### ]


# The readonly role has the following rights:
# -------------------------------------------
role_allow("readonly", action: Permission) if
    action in [
        CA_LIST,
        CA_READ,
        PUB_LIST,
        PUB_READ,
        ROUTES_READ,
        ROUTES_ANALYSIS
    ];

### TEST: [
?= role_allow("readonly", CA_LIST);
?= role_allow("readonly", CA_READ);
?= not role_allow("readonly", CA_CREATE);
?= not role_allow("readonly", CA_CREATE);
# etc
### ]


# The readwrite role has the following rights:
# --------------------------------------------
role_allow("readwrite", action: Permission) if
    action in [
        CA_LIST,
        CA_READ,
        CA_CREATE,
        CA_UPDATE,
        PUB_LIST,
        PUB_READ,
        PUB_CREATE,
        PUB_DELETE,
        ROUTES_READ,
        ROUTES_ANALYSIS,
        ROUTES_UPDATE
    ];

### TEST: [
?= role_allow("readwrite", CA_LIST);
?= role_allow("readwrite", CA_READ);
?= role_allow("readwrite", CA_CREATE);
?= role_allow("readwrite", CA_CREATE);
# etc
### ]


# The testbed role has the following rights:
# ------------------------------------------
# Note: The testbed role is a special case which is automatically assigned
# temporarily to anonymous users accessing the testbed UI/API. It should not be
# used outside of this file.
role_allow("testbed", action: Permission) if
    action in [
        CA_READ,
        CA_UPDATE,
        PUB_READ,
        PUB_CREATE,
        PUB_DELETE,
        PUB_ADMIN
    ];

### TEST: [
?= role_allow("testbed", CA_READ);
?= role_allow("testbed", CA_UPDATE);
?= role_allow("testbed", PUB_ADMIN);
?= not role_allow("testbed", ROUTES_UPDATE);
# etc
### ]