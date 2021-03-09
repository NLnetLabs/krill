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
role_allow(some_role, action: Permission, _) if
    not some_role = nil and
    not some_role.trim().is_empty() and
    action = new Permission("LOGIN");

### TEST: [
# Actors with a role can login.
?= role_allow("some role", new Permission("LOGIN"), _);
# Conversely, actors without a role cannot do anything.
?= not role_allow(nil, new Permission("LOGIN"), _);
?= not role_allow("", new Permission("LOGIN"), _);
?= not role_allow("  ", new Permission("LOGIN"), _);
?= not role_allow(nil, nil, nil);
# ?= not role_allow(nil, _, _);
### ]


# The admin role has the right to do anything with any resource:
# --------------------------------------------------------------
role_allow("admin", _action, _resource);

### TEST: [
# ?= role_allow("admin", _, _);
?= role_allow("admin", "take over", "the world");
?= not role_allow("other", "take over", "the world");
?= role_allow("admin", new Permission("CA_CREATE"), "/api/v1/cas");
### ]


# The readonly role has the following rights:
# -------------------------------------------
role_allow("readonly", action: Permission, _resource) if
    action in [
        new Permission("CA_LIST"),
        new Permission("CA_READ"),
        new Permission("PUB_LIST"),
        new Permission("PUB_READ"),
        new Permission("ROUTES_READ"),
        new Permission("ROUTES_ANALYSIS")
    ];

### TEST: [
?= role_allow("readonly", new Permission("CA_LIST"), _);
?= role_allow("readonly", new Permission("CA_READ"), "some resource");
?= not role_allow("readonly", new Permission("CA_CREATE"), _);
?= not role_allow("readonly", new Permission("CA_CREATE"), "some resource");
# etc
### ]


# The readwrite role has the following rights:
# --------------------------------------------
role_allow("readwrite", action: Permission, _resource) if
    action in [
        new Permission("CA_LIST"),
        new Permission("CA_READ"),
        new Permission("CA_CREATE"),
        new Permission("CA_UPDATE"),
        new Permission("PUB_LIST"),
        new Permission("PUB_READ"),
        new Permission("PUB_CREATE"),
        new Permission("PUB_DELETE"),
        new Permission("ROUTES_READ"),
        new Permission("ROUTES_ANALYSIS"),
        new Permission("ROUTES_UPDATE")
    ];

### TEST: [
?= role_allow("readwrite", new Permission("CA_LIST"), _);
?= role_allow("readwrite", new Permission("CA_READ"), "some resource");
?= role_allow("readwrite", new Permission("CA_CREATE"), _);
?= role_allow("readwrite", new Permission("CA_CREATE"), "some resource");
# etc
### ]


# The testbed role has the following rights:
# ------------------------------------------
# Note: The testbed role is a special case which is automatically assigned
# temporarily to anonymous users accessing the testbed UI/API. It should not be
# used outside of this file.
role_allow("testbed", action: Permission, _resource) if
    action in [
        new Permission("CA_READ"),
        new Permission("CA_UPDATE"),
        new Permission("PUB_READ"),
        new Permission("PUB_CREATE"),
        new Permission("PUB_DELETE"),
        new Permission("PUB_ADMIN")
    ];

### TEST: [
?= role_allow("testbed", new Permission("CA_READ"), _);
?= role_allow("testbed", new Permission("CA_UPDATE"), "some resource");
?= role_allow("testbed", new Permission("PUB_ADMIN"), _);
?= not role_allow("testbed", new Permission("ROUTES_UPDATE"), _);
# etc
### ]
