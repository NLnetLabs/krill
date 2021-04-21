# Important user attributes that influence the behaviour of this policy:
#   - team:     The name of one of the teams defined below in this policy file.
#   - teamrole: A role understood by Krill, either built-in or defined in a custom
#               policy file (e.g. roawrite defined in role-per-ca-demo.polar). The
#               user will have this role only for the CAs that the team is allowed
#               to work with.
#
# Examples:
#   joe   = { password_hash="...", attributes={ team="t1", teamrole="readonly" }}
#   sally = { password_hash="...", attributes={ team="t2", teamrole="readwrite" }}
#
# Assuming that Krill has CAs ca1, ca2 and ca3 then, and based on the teams
# defined below in this policy file:
#   - team "t1" only has access to CA ca1
#   - team "t2" only has access to CA ca2
#   - joe has readonly access to the CAs that his team "t1" has access to
#   - sally has readwrite access to the CAs that her team "t2" has access to


###
### team definitions (edit me)
###


# Team t1 can only work with CA ca1, they cannot see or do anything with other CAs
team_allow(team_name, ca: Handle) if
    team_name = "t1" and ca.name in ["ca1"];

# Team t2 can only work with CA ca2, they cannot see or do anything with other CAs
team_allow(team_name, ca: Handle) if
    team_name = "t2" and ca.name in ["ca2"];



################################################################################
#                YOU SHOULD NOT NEED TO EDIT BELOW THIS POINT                  #
#                TO CONFIGURE YOUR TEAMS EDIT THE LINES ABOVE                  #
################################################################################


###
### rules - evaluated at runtime (and also by the ?= tests above on load)
###


# rules for team members
#
# allow()
# +--> can_team_member_perform_action_without_resource(actor, action)
# |    +--> lookup_team_role(actor, role) 
# |    +--> role_allow(role, action, resource)
# +--> can_team_member_perform_action_on_ca(actor, action, ca)
#      +--> lookup_team_role(actor, role) 
#      +--> role_allow(role, action, ca)
#      +--> does_team_member_have_rights_on_ca(actor, ca)
#           +--> team_allow(team, ca)

can_team_member_perform_action_without_resource(actor: Actor, action: Permission) if
    lookup_team_role(actor, role) and
    role_allow(role, action);

can_team_member_perform_action_on_ca(actor: Actor, action: Permission, ca: Handle) if
    lookup_team_role(actor, role) and
    role_allow(role, action) and
    does_team_member_have_rights_on_ca(actor, ca);

is_actor_in_team(actor: Actor, team_name) if
    team_name in actor.attr("team");

does_team_member_have_rights_on_ca(actor: Actor, ca: Handle) if
    team_name in actor.attr("team") and
    team_allow(team_name, ca);

lookup_team_role(actor: Actor, out_role) if
    out_role in actor.attr("teamrole");


###
### rule activation - entrypoints used by Oso which make use of the rules above
###


allow(actor: Actor, action: Permission, nil) if
    can_team_member_perform_action_without_resource(actor, action);


allow(actor: Actor, action: Permission, ca: Handle) if
    can_team_member_perform_action_on_ca(actor, action, ca);


###
### tests
###

# test teamrole readonly
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), CA_READ, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), CA_READ, new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), CA_READ, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), CA_READ, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), CA_READ, new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), CA_READ, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), CA_UPDATE, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), CA_UPDATE, new Handle("ca3"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), CA_UPDATE, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), CA_UPDATE, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), CA_UPDATE, new Handle("ca3"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), CA_UPDATE, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), ROUTES_UPDATE, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), ROUTES_UPDATE, new Handle("ca3"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), ROUTES_UPDATE, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), ROUTES_UPDATE, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), ROUTES_UPDATE, new Handle("ca3"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), ROUTES_UPDATE, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), PUB_ADMIN, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), PUB_ADMIN, new Handle("ca3"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readonly" }), PUB_ADMIN, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), PUB_ADMIN, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), PUB_ADMIN, new Handle("ca3"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readonly" }), PUB_ADMIN, new Handle("ca2"));

# test teamrole readwrite
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), CA_READ, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), CA_READ, new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), CA_READ, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), CA_READ, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), CA_READ, new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), CA_READ, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), CA_UPDATE, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), CA_UPDATE, new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), CA_UPDATE, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), CA_UPDATE, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), CA_UPDATE, new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), CA_UPDATE, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), ROUTES_UPDATE, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), ROUTES_UPDATE, new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), ROUTES_UPDATE, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), ROUTES_UPDATE, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), ROUTES_UPDATE, new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), ROUTES_UPDATE, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), PUB_ADMIN, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), PUB_ADMIN, new Handle("ca3"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "readwrite" }), PUB_ADMIN, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), PUB_ADMIN, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), PUB_ADMIN, new Handle("ca3"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "readwrite" }), PUB_ADMIN, new Handle("ca2"));

# test teamrole admin
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), CA_READ, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), CA_READ, new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), CA_READ, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), CA_READ, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), CA_READ, new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), CA_READ, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), CA_UPDATE, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), CA_UPDATE, new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), CA_UPDATE, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), CA_UPDATE, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), CA_UPDATE, new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), CA_UPDATE, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), ROUTES_UPDATE, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), ROUTES_UPDATE, new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), ROUTES_UPDATE, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), ROUTES_UPDATE, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), ROUTES_UPDATE, new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), ROUTES_UPDATE, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), PUB_ADMIN, new Handle("ca2"));
?= not allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), PUB_ADMIN, new Handle("ca3"));
?=     allow(new Actor("t1test", { team: "t1", teamrole: "admin" }), PUB_ADMIN, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), PUB_ADMIN, new Handle("ca1"));
?= not allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), PUB_ADMIN, new Handle("ca3"));
?=     allow(new Actor("t2test", { team: "t2", teamrole: "admin" }), PUB_ADMIN, new Handle("ca2"));