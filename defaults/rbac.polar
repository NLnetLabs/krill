################################################################################
### Role Based Access Control (RBAC)
################################################################################

# 1. Assigning roles to users based on user attributes:
# =====================================================
# Appropriately set the "role" attribute on your users, e.g. if set to "admin"
# for a user it would grant that user the "admin" role. The available roles can
# be seen in the roles.polar file.

# 1a. With: "auth_type" = "config-file"
# -------------------------------------
# You can assign roles like so in your _krill.conf_ file (NOT IN THIS FILE):
# (note: to generate the password hash see `krillc config user --help`).
#
# [auth_users]
# "some@user.com" = { attributes={ role="admin" }, password_hash="xxx" }

# 1b. With: "auth_type" = "openid-connect"
# ----------------------------------------
# You will need to define a "role" claim in your _krill.conf_ file (NOT IN THIS
# FILE) which identifies a field in the OpenID Connect service JSON ID Token or
# UserInfo responses that is set to a string value equal to the name of one of
# the roles defined in the roles.polar file, e.g.:
#
# [auth_openidconnect.claims]
# role = { jmespath = "some_role_field" }
#
# Your "jmespath" may need to be more complex than this, e.g. if you need
# to use only part of the claim value as the role string.


# 2. Assigning roles through explicit rules that you define here for users
#    defined in your krill.conf file:
# ========================================================================
# You can also assign roles directly by writing an actor_has_role() rule per user
# in THIS FILE, e.g. like this:
#
# actor_has_role(actor: Actor, role: "admin") if actor.name = "some@user.com";
#
# Note: The "some@user.com" value MUST be a key under "[auth_users]" in your
# _krill.conf_ file.