################################################################################
### Role aliases
################################################################################

# Role names can be aliased so that they can be referred to, e.g. in actor
# attributes, via other names. For example the following aliases the "readonly"
# role to the name "Read Only" and does a quick sanity check to show that it
# works.
#
# role_allow("Read Only", action: Permission) if
#     role_allow("readonly", action);
#
# ?= role_allow("Read Only", CA_LIST);
