# test setup:
#
# users: (where: tN = team number, r = readonly, w = readwrite, roaw = readonly + roa write)
#    admin
#    t1ro, t1rw
#    t2ro, t2rw
#    t3ro, t3rw, t3roaw
#
# teams:
#   - t1 users: t1ro, t1rw - has role based access to ca1
#   - t2 users: t2ro, t2rw - has role based access to ca2
#   - t3 users: t3ro, t3rw - has role based access to ca1 and ca2
#        users: t3roaw     - has readonly access to ca1 and ca2, PLUS write access to ca1 ROAs
#
# users have two important attributes:
#   - team: which team they belong to
#   - teamrole: their role within the team


###
### team assignments (edit me)
###

# An alternative way of doing this might be to act as if Krill has per CA metadata like which
# teams are permitted to use which roles with the CA, and represent that as an Oso dictionary
# "returned" by a rule, but for one off exceptions like the rule for t3 below that impact
# multiple CAs that becomes quite unwieldy.


# Team t1 can only work with CA ca1, they cannot see or do anything with other CAs
is_team_member_role_permitted_on_ca(team_name, _role, ca: Handle) if
    team_name = "t1" and ca.name in ["ca1"];

# Team t2 can only work with CA ca2, they cannot see or do anything with other CAs
is_team_member_role_permitted_on_ca(team_name, _role, ca: Handle) if
    team_name = "t2" and ca.name in ["ca2"];

# Team t3 can work with CA ca2 and CA ca1, but with ca1 the only write action permitted is
# updating of ROAs. These two rules could be combined into a single rule but I find it more
# readable as two rules.
is_team_member_role_permitted_on_ca(team_name, _role, ca: Handle) if
    team_name = "t3" and ca.name in ["ca2"];

is_team_member_role_permitted_on_ca(team_name, role, ca: Handle) if
    team_name = "t3" and ca.name in ["ca1"] and role in ["roawrite", "readonly"];



################################################################################
#                   DO NOT TOUCH ANYTHING BELOW THIS POINT                     #
################################################################################


###
### rules - evaluated at runtime (and also by the ?= tests above on load)
###


# Create a role named 'roawrite' that gives users read-only access to Krill PLUS the right to update (create, delete)
# route authorizations aka ROAs:
does_role_have_permission("roawrite", action: Permission) if
    does_role_have_permission("readonly", action) or
    action = new Permission("ROUTES_UPDATE");

# Create a role named "login_and_list_cas"
does_role_have_permission("login_and_list_cas", action: Permission) if
    action in [
        new Permission("LOGIN"),
        new Permission("CA_LIST")
    ];


# rules for team members
#
# allow()
# +--> can_team_member_perform_action_without_resource(actor, action)
# |    +--> lookup_team_role(actor, role) 
# |    +--> does_role_have_permission(role, action, resource)
# +--> can_team_member_perform_action_on_ca(actor, action, ca)
#      +--> lookup_team_role(actor, role) 
#      +--> does_role_have_permission(role, action, ca)
#      +--> does_team_member_have_rights_on_ca(actor, ca)
#      |    +--> is_team_member_role_permitted_on_ca(team, role, ca)

can_team_member_perform_action_without_resource(actor: Actor, action: Permission) if
    lookup_team_role(actor, role) and
    does_role_have_permission(role, action);

# Note: This rule cannot be tested in this file because it relies on
# does_role_have_permission() which is not defined in this file. This CAN be tested using an
# Oso query from within Rust after the policy files have been loaded.
can_team_member_perform_action_on_ca(actor: Actor, action: Permission, ca: Handle) if
    lookup_team_role(actor, role) and
    does_role_have_permission(role, action) and
    does_team_member_have_rights_on_ca(actor, ca);

is_actor_in_team(actor: Actor, team_name) if
    team_name in actor.attr("team");

does_team_member_have_rights_on_ca(actor: Actor, ca: Handle) if
    team_name in actor.attr("team") and
    lookup_team_role(actor, role) and
    is_team_member_role_permitted_on_ca(team_name, role, ca);

lookup_team_role(actor: Actor, out_role) if
    out_role in actor.attr("teamrole");


###
### rule activation - entrypoints used by Oso which make use of the rules above
###


# note: when https://github.com/osohq/oso/issues/788 is fixed we will be able to replace this:
#   allow(actor: Actor, action: Permission, _resource: Option) if
#       _resource = nil and
# with this:
#   allow(actor: Actor, action: Permission, nil) if


# team member needing a permission that is NOT related to a resource
allow(actor: Actor, action: Permission, _resource: Option) if
    _resource = nil and
    can_team_member_perform_action_without_resource(actor, action);


# team member needing a permission on a specific CA
allow(actor: Actor, action: Permission, ca: Handle) if
    can_team_member_perform_action_on_ca(actor, action, ca);


# NON-team member needing a permission that is NOT related to a resource
allow(actor: Actor, action: Permission, _resource: Option) if
    _resource = nil and
    role = actor.attr("role") and
    does_role_have_permission(role, action);


# NON-team member needing a permission on a specific CA
allow(actor: Actor, action: Permission, ca: Handle) if
    role in actor.attr(ca.name) and
    does_role_have_permission(role, action);


###
### tests
###

# test teamrole readonly
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), new Permission("CA_READ"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), new Permission("CA_READ"), new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), new Permission("CA_READ"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), new Permission("CA_READ"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), new Permission("CA_READ"), new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), new Permission("CA_READ"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), new Permission("CA_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), new Permission("CA_UPDATE"), new Handle("ca3"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), new Permission("CA_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), new Permission("CA_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), new Permission("CA_UPDATE"), new Handle("ca3"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), new Permission("CA_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), new Permission("ROUTES_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), new Permission("ROUTES_UPDATE"), new Handle("ca3"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), new Permission("ROUTES_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), new Permission("ROUTES_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), new Permission("ROUTES_UPDATE"), new Handle("ca3"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), new Permission("ROUTES_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), new Permission("PUB_ADMIN"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), new Permission("PUB_ADMIN"), new Handle("ca3"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), new Permission("PUB_ADMIN"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), new Permission("PUB_ADMIN"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), new Permission("PUB_ADMIN"), new Handle("ca3"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), new Permission("PUB_ADMIN"), new Handle("ca2"));

# test teamrole readwrite
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), new Permission("CA_READ"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), new Permission("CA_READ"), new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), new Permission("CA_READ"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), new Permission("CA_READ"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), new Permission("CA_READ"), new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), new Permission("CA_READ"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), new Permission("CA_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), new Permission("CA_UPDATE"), new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), new Permission("CA_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), new Permission("CA_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), new Permission("CA_UPDATE"), new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), new Permission("CA_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), new Permission("ROUTES_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), new Permission("ROUTES_UPDATE"), new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), new Permission("ROUTES_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), new Permission("ROUTES_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), new Permission("ROUTES_UPDATE"), new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), new Permission("ROUTES_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), new Permission("PUB_ADMIN"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), new Permission("PUB_ADMIN"), new Handle("ca3"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), new Permission("PUB_ADMIN"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), new Permission("PUB_ADMIN"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), new Permission("PUB_ADMIN"), new Handle("ca3"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), new Permission("PUB_ADMIN"), new Handle("ca2"));

# test teamrole admin
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), new Permission("CA_READ"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), new Permission("CA_READ"), new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), new Permission("CA_READ"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), new Permission("CA_READ"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), new Permission("CA_READ"), new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), new Permission("CA_READ"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), new Permission("CA_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), new Permission("CA_UPDATE"), new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), new Permission("CA_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), new Permission("CA_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), new Permission("CA_UPDATE"), new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), new Permission("CA_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), new Permission("ROUTES_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), new Permission("ROUTES_UPDATE"), new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), new Permission("ROUTES_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), new Permission("ROUTES_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), new Permission("ROUTES_UPDATE"), new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), new Permission("ROUTES_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), new Permission("PUB_ADMIN"), new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), new Permission("PUB_ADMIN"), new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), new Permission("PUB_ADMIN"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), new Permission("PUB_ADMIN"), new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), new Permission("PUB_ADMIN"), new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), new Permission("PUB_ADMIN"), new Handle("ca2"));

# test non-team based access with different roles in different CAs
# as the user should not have a role that grants access to resources via rules other than those defined in this policy
# file the user won't have role="readonly" or role="readwrite" or such, but the user does need some role otherwise they
# won't be granted the right to login or to list CAs, so we use a custom role for just those "global" rights.
?= not allow(new Actor("test", {}), new Permission("LOGIN"), nil);
?=     allow(new Actor("test", { role: "login_and_list_cas" }), new Permission("LOGIN"), nil);

# note how unlike in the tests above where the team users either have full write access to a CA or they do not,
# here the user has ROUTES_UPDATE write access on one CA but has the different CA_UPDATE write access on another CA.
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), new Permission("CA_READ"), new Handle("ca3"));
?=     allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), new Permission("CA_READ"), new Handle("ca1"));
?=     allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), new Permission("CA_READ"), new Handle("ca2"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), new Permission("CA_UPDATE"), new Handle("ca3"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), new Permission("CA_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), new Permission("CA_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), new Permission("ROUTES_UPDATE"), new Handle("ca1"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), new Permission("ROUTES_UPDATE"), new Handle("ca3"));
?=     allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), new Permission("ROUTES_UPDATE"), new Handle("ca2"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), new Permission("PUB_ADMIN"), new Handle("ca3"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), new Permission("PUB_ADMIN"), new Handle("ca1"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), new Permission("PUB_ADMIN"), new Handle("ca2"));