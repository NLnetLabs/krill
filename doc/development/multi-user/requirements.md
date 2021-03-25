# Multi-User: Requirements

The primary initial requirements that influenced the architecture were:

  - Don't implement support multi-user for `krillc` or direct REST API clients at this point.
  - Target but don't restrict support to Active Directory identity providers. OpenID Connect seemed to be the modern
    standards based way to do authentication and be able to know who is authenticating and some properties about them,
    which would also be supported by Active Directory deployments (requires that they have the right components but is
    possible).

During exploration and development the understanding evolved:

  - The initial requirement to support Active Directory turned out to be a misunderstanding of what a potential customer
    used and in fact OpenID Connect turned out to be a good fit for what they actually use.
  - Support for a simple hierachy of user roles such as `admin`, `readwrite` and `readonly` may be insufficient as
    requirement discussions were fluid. Given that we don't know exactly what our customers will want to do with this
    but we do know that there are use cases around multiple internal teams, restricting access to CAs, and possibly
    needing to isolate access by customers to their own resources, the decision was made to switch to a policy engine
    rather than a hard-coded approach.
