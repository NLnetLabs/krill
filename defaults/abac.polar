################################################################################
### Attribute Based Access Control (ABAC)
################################################################################

# Restricting access to CAs per user:
# ===================================
# As with defining roles per actor, how defining CAs per actor is done depends
# also in the same way on your krill.conf.

# 1. Assigning CA access to users based on user attributes:
# =========================================================
# See roles.polar for how the "role" attribute is used, but instead use
# "inc_cas" and "exc_cas" attributes.

# 2. Assigning CA access through explicit rules that you define here for users
#    defined in your krill.conf file:
# ========================================================================
# You can also assign CA access directly by writing an actor_cannot_access_ca()
# rule per user as shown below:
#
# To deny access to one or more CAs for a specific user create a rule like so in
# THIS FILE:
#
# actor_cannot_access_ca(actor: Actor{name: "some@user.com"}, ca: Handle) if
#    ca.name in ["some_ca_handle", "some_other_ca_handle"] and cut;
#
# To grant access ONLY to one or more CAs for a specific user, create rules
# like so in THIS FILE which first block access to all CAs for the user then
# grant access to specified CAs only for that user:
#
# actor_cannot_access_ca(actor: Actor{name: "some@user.com"}, _: Handle) if
#     true;
# actor_can_access_ca(actor: Actor{name: "some@user.com"}, ca: Handle) if
#     ca.name in ["some_ca_handle", "some_other_ca_handle"];

# actor_cannot_access_ca(actor: Actor{name: "admin-token"}, ca: Handle) if
#     ca.name in ["ca2"] and cut;