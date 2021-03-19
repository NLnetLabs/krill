################################################################################
### Role aliases
################################################################################

# Role names can be aliased so that they can be referred to, e.g. in actor
# attributes, via other names. For example the following aliases the "readonly"
# role to the name "Read Only" and does a quick sanity check to show that it
# works.
#
# does_role_have_permission("Read Only", action: Permission, resource) if
#     does_role_have_permission("readonly", action, resource);
#
# ?= does_role_have_permission("Read Only", CA_LIST, _);
