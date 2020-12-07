# test setup:
#
# 5 users: admin, t1ro, t1rw, t2ro, t2rw (where: r - readonly, w - readwrite)
#
# 2 teams: t1 (users: t1ro, t1rw), t2 (users: t2ro, t2rw)
#
# 3 CAs: ca1, ca2, ca3
#        |     |    +--- only admin can see this
#        |     |
#        |     +-------- only t2 members and admin can see this
#        |
#        +-------------- only t1 members and admin can see this
#
# users have two important attributes:
#   - team: which team they belong to
#   - teamrole: their role within the team


###
### todo
###
# ?


###
### team assignments (edit me)
###
team_works_with_ca(team_name, ca: Handle) if team_name = "t1" and ca.name in ["ca1"];
team_works_with_ca(team_name, ca: Handle) if team_name = "t2" and ca.name in ["ca2"];


################################################################################
#                   DO NOT TOUCH ANYTHING BELOW THIS POINT                     #
################################################################################


###
### tests - evaluated when this file is loaded (Krill will exit on failure)
###


# sanity check
?= actor_has_role(Actor.builtin("krill"), "admin");


# verify admin can list CAs and read and write each CA
?= actor_has_role(new Actor("admin", { role: "admin" }), "admin");
?= allow(new Actor("admin", { role: "admin" }), "CA_LIST", new RequestPath("/"));
?= allow(new Actor("admin", { role: "admin" }), "CA_READ", new Handle("ca1"));
?= allow(new Actor("admin", { role: "admin" }), "CA_READ", new Handle("ca2"));
?= allow(new Actor("admin", { role: "admin" }), "CA_READ", new Handle("ca3"));
?= allow(new Actor("admin", { role: "admin" }), "CA_UPDATE", new Handle("ca1"));
?= allow(new Actor("admin", { role: "admin" }), "CA_UPDATE", new Handle("ca2"));
?= allow(new Actor("admin", { role: "admin" }), "CA_UPDATE", new Handle("ca3"));


# verify that an actor with a team attribute is considered to be in that team
# and only that team.
?= team_member_is_in_team(new Actor("t1ro", { team: "t1" }), "t1");
?= not team_member_is_in_team(new Actor("t1ro", { team: "t1" }), "t2");
?= not team_member_is_in_team(new Actor("t1ro", { team: "t1" }), nil);


# verify that team members can login
?= team_members_can_login(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "LOGIN");
?= team_members_can_login(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "LOGIN");

?= team_members_can_login(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "LOGIN");
?= team_members_can_login(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "LOGIN");


# verify that the teams work with the right CAs
?= team_works_with_ca("t1", new Handle("ca1"));
?= not team_works_with_ca("t1", new Handle("ca2"));
?= not team_works_with_ca("t1", new Handle("ca3"));

?= not team_works_with_ca("t2", new Handle("ca1"));
?= team_works_with_ca("t2", new Handle("ca2"));
?= not team_works_with_ca("t2", new Handle("ca3"));


# verify that team members work with the right CAs
?= team_member_works_with_ca(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), new Handle("ca1"));
?= not team_member_works_with_ca(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), new Handle("ca2"));
?= not team_member_works_with_ca(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), new Handle("ca3"));

?= not team_member_works_with_ca(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), new Handle("ca1"));
?= team_member_works_with_ca(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), new Handle("ca2"));
?= not team_member_works_with_ca(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), new Handle("ca3"));


# verify that team members can perform only the expected actions on the expected CAs
# this cannot be tested here, it can only be tested using an Oso query from within Rust
# after the policy files have been loaded. Or is this an Oso bug?
?= team_member_can_perform_action_on_ca(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "CA_READ", new Handle("ca1"));
?= not team_member_can_perform_action_on_ca(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "CA_READ", new Handle("ca2"));
?= not team_member_can_perform_action_on_ca(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "CA_READ", new Handle("ca3"));
?= not team_member_can_perform_action_on_ca(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "CA_UPDATE", new Handle("ca1"));
?= not team_member_can_perform_action_on_ca(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "CA_UPDATE", new Handle("ca2"));
?= not team_member_can_perform_action_on_ca(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "CA_UPDATE", new Handle("ca3"));

?= team_member_can_perform_action_on_ca(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "CA_READ", new Handle("ca1"));
?= not team_member_can_perform_action_on_ca(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "CA_READ", new Handle("ca2"));
?= not team_member_can_perform_action_on_ca(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "CA_READ", new Handle("ca3"));
?= team_member_can_perform_action_on_ca(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "CA_UPDATE", new Handle("ca1"));
?= not team_member_can_perform_action_on_ca(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "CA_UPDATE", new Handle("ca2"));
?= not team_member_can_perform_action_on_ca(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "CA_UPDATE", new Handle("ca3"));

?= not team_member_can_perform_action_on_ca(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "CA_READ", new Handle("ca1"));
?= team_member_can_perform_action_on_ca(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "CA_READ", new Handle("ca2"));
?= not team_member_can_perform_action_on_ca(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "CA_READ", new Handle("ca3"));
?= not team_member_can_perform_action_on_ca(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "CA_UPDATE", new Handle("ca1"));
?= not team_member_can_perform_action_on_ca(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "CA_UPDATE", new Handle("ca2"));
?= not team_member_can_perform_action_on_ca(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "CA_UPDATE", new Handle("ca3"));

?= not team_member_can_perform_action_on_ca(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "CA_READ", new Handle("ca1"));
?= team_member_can_perform_action_on_ca(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "CA_READ", new Handle("ca2"));
?= not team_member_can_perform_action_on_ca(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "CA_READ", new Handle("ca3"));
?= not team_member_can_perform_action_on_ca(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "CA_UPDATE", new Handle("ca1"));
?= team_member_can_perform_action_on_ca(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "CA_UPDATE", new Handle("ca2"));
?= not team_member_can_perform_action_on_ca(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "CA_UPDATE", new Handle("ca3"));


# only team members should satisfy a team member specific rule
?= not team_member_can_perform_action_on_ca(new Actor("admin", {}), "CA_READ", new Handle("ca1"));


# verify from where Oso begins evaluation, at matching allow() rules.
?= allow(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "CA_READ", new Handle("ca1"));
?= not allow(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "CA_READ", new Handle("ca2"));
?= not allow(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "CA_READ", new Handle("ca3"));
?= not allow(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "CA_UPDATE", new Handle("ca1"));
?= not allow(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "CA_UPDATE", new Handle("ca2"));
?= not allow(new Actor("t1ro", { team: "t1", teamrole: "readonly" }), "CA_UPDATE", new Handle("ca3"));

?= allow(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "CA_READ", new Handle("ca1"));
?= not allow(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "CA_READ", new Handle("ca2"));
?= not allow(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "CA_READ", new Handle("ca3"));
?= allow(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "CA_UPDATE", new Handle("ca1"));
?= not allow(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "CA_UPDATE", new Handle("ca2"));
?= not allow(new Actor("t1rw", { team: "t1", teamrole: "readwrite" }), "CA_UPDATE", new Handle("ca3"));

# verify user t2ur can read ca2 but not ca1 or ca3, and cannot write to them
?= not allow(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "CA_READ", new Handle("ca1"));
?= allow(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "CA_READ", new Handle("ca2"));
?= not allow(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "CA_READ", new Handle("ca3"));
?= not allow(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "CA_UPDATE", new Handle("ca1"));
?= not allow(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "CA_UPDATE", new Handle("ca2"));
?= not allow(new Actor("t2ro", { team: "t2", teamrole: "readonly" }), "CA_UPDATE", new Handle("ca3"));

?= not allow(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "CA_READ", new Handle("ca1"));
?= allow(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "CA_READ", new Handle("ca2"));
?= not allow(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "CA_READ", new Handle("ca3"));
?= not allow(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "CA_UPDATE", new Handle("ca1"));
?= allow(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "CA_UPDATE", new Handle("ca2"));
?= not allow(new Actor("t2rw", { team: "t2", teamrole: "readwrite" }), "CA_UPDATE", new Handle("ca3"));


###
### rules - evaluated at runtime (and also by the ?= tests above on load)
###


# rules for team members

team_member_is_in_team(actor: Actor, team_name) if
    team_name in actor.attr("team");

team_member_works_with_ca(actor: Actor, ca: Handle) if
    team_name in actor.attr("team") and
    team_works_with_ca(team_name, ca);

team_member_has_role(actor: Actor, role) if
    role in actor.attr("teamrole");

# Note: This rule cannot be tested in this file because it relies on
# role_allow() which is not defined in this file. This CAN be tested using an
# Oso query from within Rust after the policy files have been loaded.
team_member_can_perform_action_on_ca(actor: Actor, action, ca: Handle) if
    team_member_works_with_ca(actor, ca) and
    role in actor.attr("teamrole") and
    role_allow(role, action, ca);

team_member_can_perform_action_on_resource(actor: Actor, action, resource: RequestPath) if
    team_members_can_login(actor, action) or
    (
        team_member_has_role(actor, role) and
        role_allow(role, action, resource)
    );

team_members_can_login(actor: Actor, action) if
    action = "LOGIN" and
    _ in actor.attr("team") and
    _ in actor.attr("teamrole");



###
### rule activation - entrypoints used by Oso which make use of the rules above
###


allow(actor: Actor, action, resource: RequestPath) if
    team_member_can_perform_action_on_resource(actor, action, resource);


allow(actor: Actor, action, ca: Handle) if
    team_member_can_perform_action_on_ca(actor, action, ca);