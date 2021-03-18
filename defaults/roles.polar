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

# TODO: Oso maps to Option::<T>::None in Rust, but does_role_have_permission is only ever called
# with an instance of Actor, not with an Option, so this won't match?
does_role_have_permission(some_role, action: Permission) if
    not some_role = nil and action = new Permission("LOGIN");

### TEST: [
# Actors with a role can login.
?= does_role_have_permission("some role", new Permission("LOGIN"));
# Conversely, actors without a role cannot do anything.
?= not does_role_have_permission(nil, new Permission("LOGIN"));
?= not does_role_have_permission(nil, nil);
?= not does_role_have_permission(nil, _);
### ]


# The admin role has the right to do anything with any resource:
# --------------------------------------------------------------
does_role_have_permission("admin", _action);

### TEST: [
?= does_role_have_permission("admin", _);
?= does_role_have_permission("admin", "take over the world");
?= not does_role_have_permission("other", "take over the world");
?= does_role_have_permission("admin", new Permission("CA_CREATE"));
### ]


# The readonly role has the following rights:
# -------------------------------------------
does_role_have_permission("readonly", action: Permission) if
    action in [
        new Permission("CA_LIST"),
        new Permission("CA_READ"),
        new Permission("PUB_LIST"),
        new Permission("PUB_READ"),
        new Permission("ROUTES_READ"),
        new Permission("ROUTES_ANALYSIS")
    ];

### TEST: [
?= does_role_have_permission("readonly", new Permission("CA_LIST"));
?= does_role_have_permission("readonly", new Permission("CA_READ"));
?= not does_role_have_permission("readonly", new Permission("CA_CREATE"));
?= not does_role_have_permission("readonly", new Permission("CA_CREATE"));
# etc
### ]


# The readwrite role has the following rights:
# --------------------------------------------
does_role_have_permission("readwrite", action: Permission) if
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
?= does_role_have_permission("readwrite", new Permission("CA_LIST"));
?= does_role_have_permission("readwrite", new Permission("CA_READ"));
?= does_role_have_permission("readwrite", new Permission("CA_CREATE"));
?= does_role_have_permission("readwrite", new Permission("CA_CREATE"));
# etc
### ]


# The testbed role has the following rights:
# ------------------------------------------
# Note: The testbed role is a special case which is automatically assigned
# temporarily to anonymous users accessing the testbed UI/API. It should not be
# used outside of this file.
does_role_have_permission("testbed", action: Permission) if
    action in [
        new Permission("CA_READ"),
        new Permission("CA_UPDATE"),
        new Permission("PUB_READ"),
        new Permission("PUB_CREATE"),
        new Permission("PUB_DELETE"),
        new Permission("PUB_ADMIN")
    ];

### TEST: [
?= does_role_have_permission("testbed", new Permission("CA_READ"));
?= does_role_have_permission("testbed", new Permission("CA_UPDATE"));
?= does_role_have_permission("testbed", new Permission("PUB_ADMIN"));
?= not does_role_have_permission("testbed", new Permission("ROUTES_UPDATE"));
# etc
### ]