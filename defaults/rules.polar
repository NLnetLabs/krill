################################################################################
### Access rules
################################################################################


# note: using = or != with application types results in error:
#   "comparison operators are unimplemented in the oso Rust library"
# so we don't compare nil to actor.attr() results to see if an attribute is set.


################################################################################
### Check access to Krill REST APIs by requested action
################################################################################
# The action belongs to a role and thus to have access the user must have the
# required role that includes the requested action.

# Verify that the given actor has the required role to perform the requested
# action on the given relative API request path.
allow(actor: Actor, action: Permission, resource: RequestPath) if
    actor_has_role(actor, role) and
    role_allow(role, action, resource);

### TEST: [
# Sanity check: verify that the built-in master-token test actor can login.
# Exercises the rules above.
?= allow(Actor.builtin("master-token"), new Permission("LOGIN"), new RequestPath("/"));
### ]


# Assign roles to users automatically if they have a "role" attribute:
# --------------------------------------------------------------------
actor_has_role(actor: Actor, role) if role in actor.attr("role");



################################################################################
### Check access to Krill CAs by requested action and requested CA handle
################################################################################
# The action belongs to a role and thus to have access the user must have the
# required role that includes the requested action. Additionally the user must
# have explicit or implicit access to the specified CA handle, either because by
# default access isn't restricted per CA handle, or because the user is neither
# explicitly or implicitly denied access to the CA or is explicitly granted
# access to the CA.
allow(actor: Actor, action: Permission, ca: Handle) if
    actor_has_role(actor, role) and
    role_allow(role, action, ca) and
    actor_can_access_ca(actor, ca);

### TEST: [
?= allow(Actor.builtin("master-token"), new Permission("CA_READ"), new RequestPath("/"));
### ]


# Restrict access to CAs based on user "inc_cas" and "exc_cas" attributes:
# ------------------------------------------------------------------------
# Attribute values are expected to be comma-separated value strings where each
# value is a CA handle. Excludes override includes. Excludes exclude one or more
# CA handles. Includes include one or more CA handls and consequently exclude
# (deny access to) all other CA handles.
#
# Define a rule that will fail to deny access for any actor for any CA handle.
# This is the default situation, i.e. all actors have access to all CAs.
actor_cannot_access_ca(_: Actor, _: Handle) if false;

# Next define a rule that will succeed either if:
#   1.    There is no rule that explicitly blocks access to the specified CA for
#         the specified actor.
#   2a.   The actor has no "inc_cas" or "exc_cas" attributes that grant or deny
#         access to CAs, _OR_
#   2ba.  The actor has an "exc_cas" attribute which does NOT include the
#         specified CA handle (i.e. the CA is not excluded from the set the
#         actor has access), _AND_
#   2bba. The actor does not have an "inc_cas" attribute (i.e. the actor is not
#         restricted to certain CAs), _OR_
#   2bbb. The actor has an "inc_cas" attribute which includes the specified CA
#         handle (i.e. the CA is included in the set the actor is expicitly
#         given access to).
actor_can_access_ca(actor: Actor, ca: Handle) if
    # if an inline rule prevents access to the CA stop processing this rule
    not actor_cannot_access_ca(actor, ca) and

    (
    # else, if neither include nor exclude attributes exist for this actor,
    # allow access to the CA and stop processing this rule
        (not _ in actor.attr("inc_cas") and not _ in actor.attr("exc_cas")) or

    # else, if the exclude attribute exists for this actor AND the given CA
    # handle is NOT in the set of excluded CAs (which are defined as
    # comma-separated CA handle values in a single string attribute) then do not
    # exclude access yet, continue below, otherwise stop and deny access
        (_ in actor.attr("exc_cas") and not ca.name in actor.attr("exc_cas").unwrap().split(",")) or

    # else, if the include attribute does not exist for this actor then allow
    # access, otherwise only allow access if the given CA handle *IS* in the
    # include set.
        (_ in actor.attr("inc_cas") and ca.name in actor.attr("inc_cas").unwrap().split(","))
    );


### TEST: [
# test specific CA access restrictions defined inline using Polar rules
actor_cannot_access_ca(_actor: Actor{name: "dummy-test-actor2"}, ca: Handle) if
    ca.name in ["dummy-test-ca2"] and cut;

actor_cannot_access_ca(_actor: Actor{name: "dummy-test-actor3"}, ca: Handle) if
    ca.name in ["dummy-test-ca3"] and cut;

?= not actor_cannot_access_ca(new Actor("dummy-test-actor1", {}), new Handle("dummy-test-ca1"));
?= not actor_cannot_access_ca(new Actor("dummy-test-actor1", {}), new Handle("dummy-test-ca2"));
?= not actor_cannot_access_ca(new Actor("dummy-test-actor1", {}), new Handle("dummy-test-ca3"));

?= not actor_cannot_access_ca(new Actor("dummy-test-actor2", {}), new Handle("dummy-test-ca1"));
?= actor_cannot_access_ca(new Actor("dummy-test-actor2", {}), new Handle("dummy-test-ca2"));
?= not actor_cannot_access_ca(new Actor("dummy-test-actor2", {}), new Handle("dummy-test-ca3"));

?= not actor_cannot_access_ca(new Actor("dummy-test-actor3", {}), new Handle("dummy-test-ca1"));
?= not actor_cannot_access_ca(new Actor("dummy-test-actor3", {}), new Handle("dummy-test-ca2"));
?= actor_cannot_access_ca(new Actor("dummy-test-actor3", {}), new Handle("dummy-test-ca3"));

# test CA access restrictions based on actor attribute values
?= print("TEST1") and actor_can_access_ca(new Actor("a", {}), new Handle("ca1"));
?= print("TEST2") and actor_can_access_ca(new Actor("a", {inc_cas: "ca1"}), new Handle("ca1"));
?= print("TEST3") and not actor_can_access_ca(new Actor("a", {inc_cas: "ca1"}), new Handle("ca2"));
?= print("TEST4") and not actor_can_access_ca(new Actor("a", {exc_cas: "ca1"}), new Handle("ca1"));
?= print("TEST5") and actor_can_access_ca(new Actor("a", {exc_cas: "ca1"}), new Handle("ca2"));

### ]
