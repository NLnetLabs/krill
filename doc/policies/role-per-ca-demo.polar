# Important user attributes that influence the behaviour of this policy:
#   - role: Can either be a standard role giving a base level of access across all CAs or
#           the new special role introduced by this policy called "login_and_list_cas".
#   - xxx:  One or more attributes named the same as the CA to which they should assign a
#           role for the user, with the value of the attribute being the role to assign
#           for that CA.
#
# Examples:
#   joe   = { password_hash="...", attributes={ role="readonly",           ca2="readwrite" }}
#   sally = { password_hash="...", attributes={ role="login_and_list_cas", ca2="roawrite", ca3="readonly" }}
#
# Assuming that Krill has CAs ca1, ca2 and ca3 then:
#   - joe can see all of the CAs and their details
#   - joe only has write access to ca2
#   - sally can see CAs ca2 and ca3 and their details
#   - sally can update ROAs in ca2 but cannot otherwise modify ca2
#   - sally cannot see CA ca1


################################################################################
#                YOU SHOULD NOT NEED TO EDIT BELOW THIS POINT                  #
# USERS SHOULD BE CONFIGURED IN KRILL.CONF OR IN YOUR OPENID CONNECT PROVIDER  #
################################################################################


###
### rules
###


# Create a role named 'roawrite' that gives users read-only access to Krill PLUS the right to update (create, delete)
# route authorizations aka ROAs:
role_allow("roawrite", action: Permission) if
    role_allow("readonly", action) or
    action = ROUTES_UPDATE;


# Create a role named 'login_and_list_cas' that grants the rights to login and to list CAs, but no other rights:
role_allow("login_and_list_cas", action: Permission) if
    action in [LOGIN, CA_LIST];


# Grant the actor the requested permission on the specified CA ONLY if:
#   - they have a user attribute named the same as the CA, AND
#   - the value of that attribute is a role known to Krill, AND
#   - that role grants the requested permission
allow(actor: Actor, action: Permission, ca: Handle) if
    role in actor.attr(ca.name) and
    role_allow(role, action);


###
### tests
###


?= not allow(new Actor("test", {}), LOGIN, nil);
?=     allow(new Actor("test", { role: "login_and_list_cas" }), LOGIN, nil);

?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), CA_READ, new Handle("ca3"));
?=     allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), CA_READ, new Handle("ca1"));
?=     allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), CA_READ, new Handle("ca2"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), CA_UPDATE, new Handle("ca3"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), CA_UPDATE, new Handle("ca1"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), CA_UPDATE, new Handle("ca2"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), ROUTES_UPDATE, new Handle("ca1"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), ROUTES_UPDATE, new Handle("ca3"));
?=     allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), ROUTES_UPDATE, new Handle("ca2"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), PUB_ADMIN, new Handle("ca3"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), PUB_ADMIN, new Handle("ca1"));
?= not allow(new Actor("test", { ca1: "readonly", ca2: "roawrite" }), PUB_ADMIN, new Handle("ca2"));